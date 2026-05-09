import { encodeBindRequest } from "../src/rpc/dcerpc.js";
import {
  encodeNetrShareEnumRequest,
  encodeRequest,
  SRVSVC_UUID,
  SRVSVC_MAJOR,
  SRVSVC_MINOR,
} from "../src/rpc/srvsvc.js";

function hexDump(label: string, buf: Buffer): void {
  console.log(`=== ${label} (${buf.length} bytes) ===`);
  for (let i = 0; i < buf.length; i += 16) {
    const slice = buf.subarray(i, i + 16);
    const hex = [...slice].map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const asc = [...slice]
      .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "."))
      .join("");
    console.log(`${i.toString(16).padStart(4, "0")}  ${hex.padEnd(48)}  ${asc}`);
  }
  console.log();
}

const host = process.env.SMB_TEST_HOST ?? "server";

const bind = encodeBindRequest({
  callId: 1,
  abstractUuid: SRVSVC_UUID,
  abstractMajor: SRVSVC_MAJOR,
  abstractMinor: SRVSVC_MINOR,
});

const stub = encodeNetrShareEnumRequest({
  serverName: `\\\\${host}`,
  infoLevel: 1,
  preferredMaximumLength: 0xffffffff,
});

const req = encodeRequest({ callId: 2, opnum: 15, contextId: 0, stub });

hexDump("BIND PDU", bind);
hexDump("NetrShareEnum STUB (NDR)", stub);
hexDump("REQUEST PDU (full)", req);

// Annotate bind frame fields
console.log("=== BIND field annotations ===");
console.log(`RpcVersion:    0x${bind[0]!.toString(16).padStart(2,"0")}`);
console.log(`MinorVersion:  0x${bind[1]!.toString(16).padStart(2,"0")}`);
console.log(`PacketType:    0x${bind[2]!.toString(16).padStart(2,"0")} (0x0b=Bind)`);
console.log(`PacketFlags:   0x${bind[3]!.toString(16).padStart(2,"0")} (0x03=First+Last)`);
console.log(`DataRep:       ${[...bind.subarray(4,8)].map(b=>b.toString(16).padStart(2,"0")).join(" ")}`);
console.log(`FragLength:    ${bind.readUInt16LE(8)} (offset 8)`);
console.log(`AuthLength:    ${bind.readUInt16LE(10)}`);
console.log(`CallId:        ${bind.readUInt32LE(12)}`);
console.log(`MaxXmitFrag:   ${bind.readUInt16LE(16)}`);
console.log(`MaxRecvFrag:   ${bind.readUInt16LE(18)}`);
console.log(`AssocGroupId:  ${bind.readUInt32LE(20)}`);
console.log(`NumCtxItems:   ${bind[24]!}`);
console.log(`Padding[25-27]: ${[...bind.subarray(25,28)].map(b=>b.toString(16).padStart(2,"0")).join(" ")}`);
console.log(`CtxId:         ${bind.readUInt16LE(28)}`);
console.log(`NumTransSyn:   ${bind[30]!}`);
console.log(`Pad[31]:       ${bind[31]!.toString(16)}`);
console.log(`AbstractUUID:  ${[...bind.subarray(32,48)].map(b=>b.toString(16).padStart(2,"0")).join(" ")}`);
console.log(`AbstractVer:   major=${bind.readUInt16LE(48)} minor=${bind.readUInt16LE(50)}`);
console.log(`TransferUUID:  ${[...bind.subarray(52,68)].map(b=>b.toString(16).padStart(2,"0")).join(" ")}`);
console.log(`TransferVer:   major=${bind.readUInt16LE(68)} minor=${bind.readUInt16LE(70)}`);

console.log();
console.log("=== STUB field annotations ===");
let off = 0;
console.log(`[${off}] ServerName referent: 0x${stub.readUInt32LE(off).toString(16)}`); off += 4;
// ndrUtf16 for \\\\host:
const max = stub.readUInt32LE(off); console.log(`[${off}] max_count: ${max}`); off += 4;
const ooff = stub.readUInt32LE(off); console.log(`[${off}] offset: ${ooff}`); off += 4;
const actual = stub.readUInt32LE(off); console.log(`[${off}] actual_count: ${actual}`); off += 4;
const strBytes = actual * 2;
const str = stub.subarray(off, off + strBytes);
console.log(`[${off}] string bytes (${strBytes}): ${[...str].map(b=>b.toString(16).padStart(2,"0")).join(" ")}`);
off += strBytes;
// padding
while (off % 4 !== 0) { console.log(`[${off}] pad byte: ${stub[off]!.toString(16)}`); off++; }
console.log(`[${off}] SHARE_ENUM_STRUCT Level: ${stub.readUInt32LE(off)}`); off += 4;
console.log(`[${off}] Union tag: ${stub.readUInt32LE(off)}`); off += 4;
console.log(`[${off}] Container ptr: 0x${stub.readUInt32LE(off).toString(16)}`); off += 4;
console.log(`[${off}] EntriesRead: ${stub.readUInt32LE(off)}`); off += 4;
console.log(`[${off}] Buffer ptr: 0x${stub.readUInt32LE(off).toString(16)}`); off += 4;
console.log(`[${off}] PrefMaxLen: 0x${stub.readUInt32LE(off).toString(16)}`); off += 4;
console.log(`[${off}] ResumeHandle ptr: 0x${stub.readUInt32LE(off).toString(16)}`); off += 4;
console.log(`Total stub length: ${stub.length}`);
