const fs = require("fs");
const path = require("path");
const process = require("process");
const yaml = require("js-yaml");
const axios = require("axios");
const readline = require("readline");

let Cap;
let decoders;
let PROTOCOL;

function baseDir() {
  return process.pkg ? path.dirname(process.execPath) : process.cwd();
}

function loadConfig() {
  const cfgPath = path.resolve(baseDir(), process.env.CONFIG || "config.yaml");
  if (!fs.existsSync(cfgPath)) {
    throw new Error(`config file not found: ${cfgPath}`);
  }
  const content = fs.readFileSync(cfgPath, "utf8");
  const cfg = yaml.load(content) || {};
  if (!cfg.webhook || !cfg.webhook.guild) {
    throw new Error("config.yaml must define webhook.guild");
  }
  return cfg;
}

function buildBpf() {
  return "ip and tcp";
}

function isVirtual(name = "") {
  const lower = name.toLowerCase();
  return ["zerotier", "vmware", "hyper-v", "virtual", "loopback", "tap", "bluetooth", "wan miniport"].some((k) => lower.includes(k));
}

function chooseInterface(cfg, devices) {
  const physical = devices.filter((d) => !isVirtual(d.description || d.name));
  if (physical.length === 0) return devices[0];
  return physical[0];
}

function waitForEnter(message, code = 1) {
  console.error(message);
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question("Press Enter to exit...", () => {
      rl.close();
      resolve(code);
    });
  }).then((c) => {
    process.exit(c);
  });
}

async function sendWebhook(url, content) {
  if (!url) return;
  try {
    await axios.post(url, { username: "Guild-Chat", content });
  } catch (e) {
    console.error(`webhook error: ${e}`);
  }
}

function makeFlowKey(srcaddr, srcport, dstaddr, dstport) {
  return `${srcaddr}:${srcport}->${dstaddr}:${dstport}`;
}

// ---- Chat payload helpers (proto-like TLV) ----
function readVarint(buf, offset) {
  let val = 0n;
  let shift = 0n;
  let pos = offset;
  while (pos < buf.length) {
    const b = buf[pos];
    val |= BigInt(b & 0x7f) << shift;
    pos += 1;
    if ((b & 0x80) === 0) break;
    shift += 7n;
  }
  return { value: val, next: pos };
}

function parseFields(buf) {
  const fields = [];
  let off = 0;
  while (off < buf.length) {
    const tagVar = readVarint(buf, off);
    if (tagVar.next > buf.length) break;
    const tag = Number(tagVar.value);
    off = tagVar.next;
    const fieldNumber = tag >> 3;
    const wireType = tag & 0x07;
    if (wireType === 2) {
      const lenVar = readVarint(buf, off);
      if (lenVar.next > buf.length) break;
      const len = Number(lenVar.value);
      off = lenVar.next;
      const end = Math.min(off + len, buf.length);
      const data = buf.subarray(off, end);
      fields.push({ fieldNumber, wireType, len, data });
      off = end;
    } else if (wireType === 0) {
      const v = readVarint(buf, off);
      fields.push({ fieldNumber, wireType, value: v.value });
      off = v.next;
    } else {
      break; // unsupported wire type
    }
  }
  return fields;
}

function unwrapEmbedded(fields, maxDepth = 2) {
  let out = fields;
  let depth = 0;
  while (depth < maxDepth && out.length === 1 && out[0].wireType === 2) {
    out = parseFields(out[0].data);
    depth += 1;
  }
  return out;
}

function safeUtf8(buf) {
  try {
    return Buffer.from(buf).toString("utf8");
  } catch (_e) {
    return "";
  }
}

function parseChatEnvelope(restBuf) {
  const fields = parseFields(restBuf);
  const body = unwrapEmbedded(fields);
  let channel;
  let senderName;
  let message;

  function applySenderBlock(buf) {
    const user = parseFields(buf);
    for (const uf of user) {
      if (uf.fieldNumber === 2 && uf.wireType === 2) senderName = safeUtf8(uf.data);
    }
    if (!senderName) {
      const asText = safeUtf8(buf);
      if (asText) senderName = asText;
    }
  }

  function applyContentBlock(buf) {
    const sub = parseFields(buf);
    for (const sf of sub) {
      if (sf.fieldNumber === 3 && sf.wireType === 2) message = safeUtf8(sf.data);
    }
  }

  for (const f of body) {
    if (f.fieldNumber === 1 && f.wireType === 0) channel = Number(f.value);
    if (f.fieldNumber === 2 && f.wireType === 2) {
      const sub = parseFields(f.data);
      for (const sf of sub) {
        if (sf.fieldNumber === 2 && sf.wireType === 2) applySenderBlock(sf.data);
        if (sf.fieldNumber === 4 && sf.wireType === 2) applyContentBlock(sf.data);
      }
    }
    if (f.fieldNumber === 4 && f.wireType === 2) applyContentBlock(f.data);
  }
  if (channel === undefined && senderName === undefined && message === undefined) return null;
  return { channel, senderName, message };
}

class TcpReassembler {
  constructor(handleFrame) {
    this.handleFrame = handleFrame;
    this.buffer = Buffer.alloc(0);
    this.nextSeq = -1;
    this.cache = new Map();
  }

  ingest(seq, payload) {
    if (payload.length === 0) return;
    if (this.nextSeq === -1) this.nextSeq = seq;

    if (seq < this.nextSeq) {
      const offset = this.nextSeq - seq;
      if (offset >= payload.length) return;
      payload = payload.subarray(offset);
      seq = this.nextSeq;
    }

    if (seq !== this.nextSeq) {
      this.cache.set(seq, payload);
      return;
    }

    this._append(payload);

    while (this.cache.has(this.nextSeq)) {
      const buf = this.cache.get(this.nextSeq);
      this.cache.delete(this.nextSeq);
      this._append(buf);
    }

    this._drainFrames();
  }

  _append(buf) {
    this.buffer = this.buffer.length === 0 ? buf : Buffer.concat([this.buffer, buf]);
    this.nextSeq = (this.nextSeq + buf.length) >>> 0;
  }

  _drainFrames() {
    while (this.buffer.length >= 4) {
      const len = this.buffer.readUInt32BE(0);
      if (len <= 0 || len > 0x0fffff) {
        this.buffer = Buffer.alloc(0);
        return;
      }
      if (this.buffer.length < len) return;
      const frame = this.buffer.subarray(0, len);
      this.buffer = this.buffer.subarray(len);
      this.handleFrame(frame);
    }
  }
}

class GuildMirror {
  constructor(cfg) {
    this.cfg = cfg;
    this.guildWebhook = cfg.webhook?.guild || "";
    this.flows = [];
    this.debug = { verbose: false };
  }

  maybeDetectServer(payload, srcKey, dstKey) {
    if (payload.length < 12) return;
    const sig = Buffer.from([0x00, 0x06, 0x26, 0xad, 0x66, 0x00]);
    for (let i = 0; i + sig.length <= payload.length; i++) {
      if (payload.subarray(i, i + sig.length).compare(sig) === 0) {
        this.bindFlow(srcKey, dstKey, "sig");
        return;
      }
    }
  }

  bindFlow(srcKey, dstKey, reason = "filter") {
    const flow = {
      serverSrcKey: srcKey,
      serverDstKey: dstKey,
      reassemblers: {
        downstream: new TcpReassembler((frame) => this.handleFrame(frame, "downstream")),
        upstream: new TcpReassembler((frame) => this.handleFrame(frame, "upstream")),
      },
    };
    this.flows.push(flow);
    if (this.debug && this.debug.verbose) console.log(`Bound flow (${reason}): serverSrcKey=${srcKey} serverDstKey=${dstKey}`);
    return flow;
  }

  findFlow(key) {
    return this.flows.find((f) => f.serverSrcKey === key || f.serverDstKey === key);
  }

  handleFrame(frame, dir) {
    if (frame.length < 6) return;
    const packetType = frame.readUInt16BE(4);
    const msgType = packetType & 0x7fff;

    if (msgType === 1 || msgType === 2 || msgType === 3) {
      const payload = frame.subarray(6);
      const rest = payload.subarray(Math.min(payload.length, 16));
      const chat = parseChatEnvelope(rest);
      if (chat && chat.message) {
        const sender = chat.senderName || "?";

        if (chat.channel === 4) {
          const content = `${sender}: ${chat.message}`;
          this.dispatch({ channel: "guild", text: content });
          console.log(content);
        }
      }
    }
  }

  dispatch(evt) {
    if (evt.channel === "guild") {
      sendWebhook(this.guildWebhook, evt.text);
    }
  }

  handlePacket(srcaddr, dstaddr, tcp, payload) {
    const srcKey = makeFlowKey(srcaddr, tcp.info.srcport, dstaddr, tcp.info.dstport);
    const dstKey = makeFlowKey(dstaddr, tcp.info.dstport, srcaddr, tcp.info.srcport);

    let flow = this.findFlow(srcKey);

    if (!flow) {
      flow = this.bindFlow(srcKey, dstKey, "auto");
      if (!this.findFlow(dstKey)) {
        this.bindFlow(dstKey, srcKey, "auto-reverse");
      }
    }

    let dir = null;
    if (srcKey === flow.serverSrcKey) {
      dir = "downstream";
    } else if (srcKey === flow.serverDstKey) {
      dir = "upstream";
    } else {
      return;
    }

    if (!flow.reassemblers[dir]) {
      flow.reassemblers[dir] = new TcpReassembler((frame) => this.handleFrame(frame, dir));
    }
    flow.reassemblers[dir].ingest(tcp.info.seqno >>> 0, payload);
  }
}

async function main() {
  try {
    const exeDir = baseDir();
    process.chdir(exeDir);

    let cap;
    try {
      cap = require("cap");
    } catch (e) {
      await waitForEnter(`failed to load cap native module (cap.node). Place cap.node next to exe. ${e}`);
      return;
    }
    Cap = cap.Cap;
    decoders = cap.decoders;
    PROTOCOL = decoders.PROTOCOL;

    const cfg = loadConfig();
    const devices = Cap.deviceList();
    if (!devices || devices.length === 0) {
      await waitForEnter("no capture devices found (Npcap/WinPcap required)");
      return;
    }
    const chosen = chooseInterface(cfg, devices);
    if (!chosen) {
      await waitForEnter("failed to select interface");
      return;
    }

    const filter = buildBpf();
    console.log(`Using interface: ${chosen.name} (${chosen.description})`);
    console.log(`BPF filter: ${filter}`);

    const buffer = Buffer.alloc(65535);
    const c = new Cap();
    const linkType = c.open(chosen.name, filter, 10 * 1024 * 1024, buffer);
    if (!["ETHERNET", "NULL", "LINKTYPE_LINUX_SLL"].includes(linkType)) {
      console.warn(`unexpected link type ${linkType}`);
    }
    c.setMinBytes && c.setMinBytes(0);

    const mirror = new GuildMirror(cfg);

    c.on("packet", (nbytes) => {
      try {
        const packetBuf = buffer.subarray(0, nbytes);
        let eth;
        if (linkType === "ETHERNET") {
          eth = decoders.Ethernet(packetBuf);
        } else if (linkType === "NULL") {
          eth = {
            info: {
              dstmac: "00:00:00:00:00:00",
              srcmac: "00:00:00:00:00:00",
              type: packetBuf.readUInt32LE(0) === 2 ? 2048 : 0,
            },
            offset: 4,
          };
        } else {
          return;
        }

        if (eth.info.type !== PROTOCOL.ETHERNET.IPV4) return;
        const ip = decoders.IPV4(packetBuf, eth.offset);
        if (ip.info.protocol !== PROTOCOL.IP.TCP) return;

        const tcp = decoders.TCP(packetBuf, ip.offset);
        const payloadLen = ip.info.totallen - ip.hdrlen - tcp.hdrlen;
        if (payloadLen <= 0 || tcp.offset + payloadLen > packetBuf.length) return;
        const payload = Buffer.from(packetBuf.subarray(tcp.offset, tcp.offset + payloadLen));
        mirror.handlePacket(ip.info.srcaddr, ip.info.dstaddr, tcp, payload);
      } catch (e) {
        console.error(`packet error: ${e}`);
      }
    });

    console.log("listening... close window or press Ctrl+C to stop");
  } catch (err) {
    await waitForEnter(err.message || String(err));
  }
}

process.on("uncaughtException", async (err) => {
  await waitForEnter(`uncaughtException ${err}`);
});
process.on("unhandledRejection", async (err) => {
  await waitForEnter(`unhandledRejection ${err}`);
});

main();
