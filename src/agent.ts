import {
  Initialize,
  setPrivateFindings,
  BlockEvent,
  HandleBlock,
  Finding,
  getLabels,
  LabelsResponse,
  Label,
  getBotId,
} from "forta-agent";
import { RugPullResult, RugPullPayload, FalsePositiveInfo, FalsePositiveDatabase } from "./types";
import {
  createRugPullFinding,
  createContractFalsePositiveFinding,
  createDeployerFalsePositiveFinding,
} from "./findings";
import WebSocket, { MessageEvent, ErrorEvent, CloseEvent } from "ws";
import axios from "axios";

// `123` URL for testing
const webSocketUrl = "ws://localhost:1234";
// PROD URL
// const wsUrl = "";
const falsePositiveUrl = "";
let ownBotId: string;

// const ws: WebSocket = new WebSocket(wsUrl);
const unalertedRugPullResults: RugPullResult[] = [];
const alertedFalsePositives: string[] = [];
let isWebSocketConnected: boolean;

async function fetchLabels(entityAddress: string, entityLabel: string): Promise<Label[]> {
  const labels: Label[] = [];
  let hasNext = true;
  let startingCursor = undefined;

  while (hasNext) {
    const results: LabelsResponse = await getLabels({
      entities: [entityAddress],
      labels: [entityLabel],
      sourceIds: [ownBotId],
      entityType: "Address",
    });

    hasNext = results.pageInfo.hasNextPage;
    startingCursor = results.pageInfo.endCursor;

    results.labels.forEach((label: Label) => {
      labels.push(label);
    });
  }

  return labels;
}

async function establishNewWebSocketClient(ws: WebSocket) {
  ws.onopen = () => {
    isWebSocketConnected = true;
    console.log("WebSocket connection opened.");
  };

  ws.onmessage = (message: MessageEvent) => {
    const parsedData: RugPullPayload = JSON.parse(message.data.toString());
    parsedData.result.forEach((result: RugPullResult) => {
      unalertedRugPullResults.push(result);
    });
  };

  ws.onerror = (error: ErrorEvent) => {
    isWebSocketConnected = false;
    console.log(`WebSocket connection errored out. Type: ${error.type}`);
  };

  ws.onclose = (event: CloseEvent) => {
    isWebSocketConnected = false;
    console.log(`WebSocket connection closed. Code: ${event.code}.`);
  };

  isWebSocketConnected = true;
}

async function fetchFalsePositiveList(falsePositiveUrl: string): Promise<FalsePositiveDatabase> {
  return (await axios.get(falsePositiveUrl)).data;
}

export function provideInitialize(ws: WebSocket): Initialize {
  return async () => {
    setPrivateFindings(true);
    establishNewWebSocketClient(ws);
    ownBotId = getBotId();
  };
}

export function provideHandleBlock(
  falsePositiveUrl: string,
  falsePositiveFetcher: any,
  labelFetcher: any
): HandleBlock {
  return async (blockEvent: BlockEvent): Promise<Finding[]> => {
    if (!isWebSocketConnected) {
      establishNewWebSocketClient(new WebSocket(webSocketUrl));
    }

    const findings: Finding[] = [];

    if (blockEvent.blockNumber % 300 == 0) {
      const falsePositiveDb: FalsePositiveDatabase = await falsePositiveFetcher(falsePositiveUrl);

      Object.values(falsePositiveDb).forEach(async (fpEntry: FalsePositiveInfo) => {
        if (!alertedFalsePositives.includes(fpEntry["contractName"])) {
          await labelFetcher(fpEntry["contractAddress"], "Rug pull contract").forEach((label: Label) => {
            findings.push(
              createContractFalsePositiveFinding(
                fpEntry,
                label.metadata.chainId,
                label.metadata.contractAddress,
                label.metadata.deployerAddress,
                label.metadata.creationTime,
                label.metadata.contractName,
                label.metadata.tokenSymbol,
                label.metadata.exploitId,
                label.metadata.exploitName,
                label.metadata.exploitType
              )
            );
          });
          await labelFetcher(fpEntry["deployerAddress"], "Rug pull contract deployer").forEach((label: Label) => {
            findings.push(
              createDeployerFalsePositiveFinding(
                fpEntry,
                label.metadata.chainId,
                label.metadata.contractAddress,
                label.metadata.deployerAddress,
                label.metadata.creationTime,
                label.metadata.contractName,
                label.metadata.tokenSymbol,
                label.metadata.exploitId,
                label.metadata.exploitName,
                label.metadata.exploitType
              )
            );
          });
          alertedFalsePositives.push(fpEntry["contractName"]);
        }
      });
    }

    const rugPullEntriesAmount: number = unalertedRugPullResults.length;
    // Check to not exceed 50 alert finding
    if (rugPullEntriesAmount > 50) {
      for(let i = 0; i < 50; i++) {
        findings.push(createRugPullFinding(unalertedRugPullResults[i]));
      }
      unalertedRugPullResults.splice(0, 50);
    } else if (rugPullEntriesAmount > 0 && rugPullEntriesAmount < 50) {
      unalertedRugPullResults.forEach((result: RugPullResult) => {
        findings.push(createRugPullFinding(result));
      });
      unalertedRugPullResults.splice(0, rugPullEntriesAmount);
    }

    return findings;
  };
}

export default {
  // initialize: provideInitialize(ws),
  // handleBlock: provideHandleBlock(falsePositiveUrl, fetchFalsePositiveList, fetchLabels),
  provideInitialize,
  provideHandleBlock,
};
