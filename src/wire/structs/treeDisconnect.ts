export function encodeTreeDisconnectRequest(): Buffer {
  // StructureSize(2)=4, Reserved(2)
  return Buffer.from([0x04, 0x00, 0x00, 0x00]);
}
