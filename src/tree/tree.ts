import type { Connection } from "../connection/connection.js";
import type { Session } from "../session/session.js";
import { encodeTreeConnectRequest, decodeTreeConnectResponse, ShareType } from "../wire/structs/treeConnect.js";
import { encodeTreeDisconnectRequest } from "../wire/structs/treeDisconnect.js";
import { SmbCommand, isSuccess, statusName } from "../wire/commands.js";
import { SmbError } from "../errors.js";

export class Tree {
  private constructor(
    public readonly conn: Connection,
    public readonly session: Session,
    public readonly path: string,
    public readonly treeId: number,
    public readonly shareType: ShareType,
    public readonly maximalAccess: number,
  ) {}

  static async connect(conn: Connection, session: Session, sharePath: string): Promise<Tree> {
    const body = encodeTreeConnectRequest({ path: sharePath });
    const signing = session.makeSigning();
    const resp = await conn.send(SmbCommand.TREE_CONNECT, body, {
      sessionId: session.sessionId,
      ...(signing !== undefined ? { signing } : {}),
      creditCharge: 1,
    });
    if (!isSuccess(resp.header.status)) {
      throw new SmbError({ status: resp.header.status, message: `TREE_CONNECT failed: ${statusName(resp.header.status)}` });
    }
    const tcr = decodeTreeConnectResponse(resp.body);
    if (resp.header.treeId === undefined) throw new Error("TREE_CONNECT: server did not return TreeId");
    return new Tree(conn, session, sharePath, resp.header.treeId, tcr.shareType, tcr.maximalAccess);
  }

  async disconnect(): Promise<void> {
    const body = encodeTreeDisconnectRequest();
    const signing = this.session.makeSigning();
    await this.conn.send(SmbCommand.TREE_DISCONNECT, body, {
      sessionId: this.session.sessionId,
      treeId: this.treeId,
      ...(signing !== undefined ? { signing } : {}),
      creditCharge: 1,
    });
  }
}
