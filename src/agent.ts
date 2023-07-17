import {
  BlockEvent,
  HandleBlock,
  Finding,
  FindingType,
  FindingSeverity,
  Label,
  EntityType,
  ethers
} from "forta-agent";
import WebSocket from 'ws';

const ws: WebSocket = new WebSocket('/*endpoint file path*/');

let rugPullDataHashAlreadyUsed;
let rawRugPullData: any = [];
let isTaskRunning = false;

function hashProperties(
  createdAt: string, 
  deployerAddress: string,
  address: string,
  chainId: string
) {
  const str = createdAt + deployerAddress + address + chainId;
  return ethers.utils.keccak256(ethers.utils.toUtf8Bytes(str));
}

async function runLongTask(ws: WebSocket) {
  isTaskRunning = true;

  ws.on('message', function message(data: any) {
    data["result"].forEach((result: any) => {
      const resultHash: string = hashProperties(
        result["created_at"],
        result["deployer_addr"],
        result["address"],
        result["chain_id"]
      );

      // Check if `resultHash` has been stored in `rugPullDataHashAlreadyUsed`

      // and if data not found in rugPullDataHashAlreadyUsed, then...
      rawRugPullData.push(result);

      // Push `resultHash` to `rugPullDataHashAlreadyUsed`
    });
  });

  ws.on('error', console.error);

  isTaskRunning = false;
}

export function provideHandleBlock(ws: WebSocket): HandleBlock {
  // make sure only one task is running at a time
  if (!isTaskRunning) {
    runLongTask(ws);
  }

  return async (blockEvent: BlockEvent): Promise<Finding[]> => {
    const findings: Finding[] = [];

    const rugPullEntries: number = rawRugPullData.length;
    if(rugPullEntries > 0) {
      rawRugPullData.forEach((entry: any) => {
        findings.push(
          Finding.fromObject({
            name: "Rug pull contract detected",
            description: entry["exploits"]["name"],
            alertId: "",
            severity: FindingSeverity.Critical,
            type: FindingType.Scam,
            metadata: {
              chainId: entry["chain_id"],
              deployerAddress: entry["deployer_addr"],
              createdAddress: entry["address"],
              creationTime: entry["created_at"],
              tokenName: entry["name"],
              tokenSymbol: entry["symbol"],
              exploitName: entry["exploits"]["name"],
              exploitType: entry["exploits"]["type"]
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
  handleBlock: provideHandleBlock(ws)
};