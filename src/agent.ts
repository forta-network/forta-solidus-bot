import {
  BlockEvent,
  HandleBlock,
  Finding,
  FindingType,
  FindingSeverity,
  Label,
  EntityType
} from "forta-agent";
import WebSocket from 'ws';

// const ws: WebSocket = new WebSocket('ws://localhost:1234');
let rawRugPullData: any = [];
let isTaskRunning = false;

async function runLongTask(ws: WebSocket) {
  isTaskRunning = true;

  ws.onmessage = (message: any) => {
    const parsedData = JSON.parse(message["data"]);
    parsedData.result.forEach((result: any) => {
      rawRugPullData.push(result);
    });
  };

  isTaskRunning = false;
}

export function provideHandleBlock(ws: WebSocket): HandleBlock {
  return async (blockEvent: BlockEvent): Promise<Finding[]> => {
    // make sure only one task is running at a time
    if (!isTaskRunning) {
      runLongTask(ws);
    }

    const findings: Finding[] = [];

    const rugPullEntries: number = rawRugPullData.length;
    if(rugPullEntries > 0) {
      rawRugPullData.forEach((entry: any) => {
        findings.push(
          Finding.fromObject({
            name: "Rug pull contract detected",
            description: entry["exploits"][0]["name"],
            alertId: "SOLIDUS-RUG-PULL",
            severity: FindingSeverity.Critical,
            type: FindingType.Scam,
            metadata: {
              chainId: entry["chain_id"],
              deployerAddress: entry["deployer_addr"],
              createdAddress: entry["address"],
              creationTime: entry["created_at"],
              tokenName: entry["name"],
              tokenSymbol: entry["symbol"],
              exploitName: entry["exploits"][0]["name"],
              exploitType: entry["exploits"][0]["type"]
            },
            labels: [
              Label.fromObject({
                entity: entry["address"],
                entityType: EntityType.Address,
                label: "Rug pull contract",
                confidence: 0.99,
                remove: false,
                createdAt: entry["created_at"]
              }),
              Label.fromObject({
                entity: entry["deployer_addr"],
                entityType: EntityType.Address,
                label: "Rug pull contract deployer",
                confidence: 0.99,
                remove: false,
              }),
            ]
          })
        );
      });

      rawRugPullData.splice(0, rugPullEntries);
    }

    return findings;
  }
};

export default {
  provideHandleBlock,
  // handleBlock: provideHandleBlock(ws)
};