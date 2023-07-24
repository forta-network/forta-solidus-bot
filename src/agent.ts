import {
  Initialize,
  setPrivateFindings,
  BlockEvent,
  HandleBlock,
  Finding,
  getLabels,
  LabelsResponse,
  Label,
} from "forta-agent";
import WebSocket, { MessageEvent, ErrorEvent, CloseEvent } from "ws";
import axios from "axios";
import { RugPullResult, RugPullPayload, FalsePositiveInfo, FalsePositiveDatabase } from "./types";
import { createRugPullFinding, createFalsePositiveFinding } from "./findings";

// `123` URL for testing
const WEBSOCKET_URL: string = "ws://localhost:1234";
// PROD URL
// const WEBSOCKET_URL = "";
const FP_DB_URL: string =
  "https://raw.githubusercontent.com/forta-network/forta-solidus-bot/main/false.positive.database.json";
const BOT_ID: string = "0x1ae0e0734a5d2b4ab26b8f63b5c323cceb8ecf9ac16d1276fcb399be0923567a";
const MAX_RUG_PULL_RESULTS_PER_BLOCK: number = 50;

// const ws: WebSocket = new WebSocket(WEBSOCKET_URL);
const unalertedRugPullResults: RugPullResult[] = [];
const alertedFalsePositives: string[] = [];
let isWebSocketConnected: boolean;

async function fetchLabels(falsePositiveEntry: FalsePositiveInfo): Promise<Label[]> {
  const labels: Label[] = [];
  let hasNext = true;

  while (hasNext) {
    const results: LabelsResponse = await getLabels({
      entities: [falsePositiveEntry["contractAddress"], falsePositiveEntry["deployerAddress"]],
      labels: ["Rug pull contract", "Rug pull contract deployer"],
      sourceIds: [BOT_ID],
      entityType: "Address",
    });

    hasNext = results.pageInfo.hasNextPage;

    results.labels.forEach((label: Label) => {
      labels.push(label);
    });
  }

  return labels;
}

function establishNewWebSocketClient(ws: WebSocket) {
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
    console.log(`WebSocket connection errored out. Type: ${error.type}.`);
  };

  ws.onclose = (event: CloseEvent) => {
    isWebSocketConnected = false;
    console.log(`WebSocket connection closed. Code: ${event.code}. Reason (could be empty): ${event.reason}`);
  };

  isWebSocketConnected = true;
}

async function fetchFalsePositiveList(falsePositiveDbUrl: string): Promise<FalsePositiveDatabase> {
  const retryCount = 3;
  let falsePositiveDb = {};

  for (let i = 0; i <= retryCount; i++) {
    try {
      falsePositiveDb = (await axios.get(falsePositiveDbUrl)).data;
      break;
    } catch (e) {
      if (i === retryCount) {
        console.log("Error fetching false positive database.");
      }
    }
  }

  return falsePositiveDb;
}

export function provideInitialize(ws: WebSocket): Initialize {
  return async () => {
    setPrivateFindings(true);
    establishNewWebSocketClient(ws);
  };
}

export function provideHandleBlock(
  falsePositiveDbUrl: string,
  falsePositiveFetcher: (url: string) => Promise<FalsePositiveDatabase>,
  labelFetcher: (falsePositiveEntry: FalsePositiveInfo) => Promise<Label[]>
): HandleBlock {
  return async (blockEvent: BlockEvent): Promise<Finding[]> => {
    if (!isWebSocketConnected) {
      establishNewWebSocketClient(new WebSocket(WEBSOCKET_URL));
    }

    const findings: Finding[] = [];

    if (blockEvent.blockNumber % 300 == 0) {
      const falsePositiveDb: FalsePositiveDatabase = await falsePositiveFetcher(falsePositiveDbUrl);

      await Promise.all(
        Object.values(falsePositiveDb).map(async (fpEntry: FalsePositiveInfo) => {
          (await labelFetcher(fpEntry)).forEach((label: Label) => {
            if (!alertedFalsePositives.includes(fpEntry["contractName"])) {
              findings.push(createFalsePositiveFinding(fpEntry, label.metadata));
              alertedFalsePositives.push(fpEntry["contractName"]);
            }
          });
        })
      );
    }

    const resultsToBeProcessed: RugPullResult[] = unalertedRugPullResults.splice(
      0,
      Math.min(unalertedRugPullResults.length, MAX_RUG_PULL_RESULTS_PER_BLOCK)
    );
    findings.push(...resultsToBeProcessed.map(createRugPullFinding));

    return findings;
  };
}

export default {
  // initialize: provideInitialize(ws),
  // handleBlock: provideHandleBlock(FP_DB_URL, fetchFalsePositiveList, fetchLabels),
  provideInitialize,
  provideHandleBlock,
};
