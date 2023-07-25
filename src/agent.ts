import { Initialize, setPrivateFindings, BlockEvent, HandleBlock, Finding, Label } from "forta-agent";
import WebSocket, { MessageEvent, ErrorEvent, CloseEvent } from "ws";
import { MAX_RUG_PULL_RESULTS_PER_BLOCK, FP_CSV_PATH, WEBSOCKET_URL } from "./constants";
import { RugPullResult, RugPullPayload, FalsePositiveEntry } from "./types";
import { createRugPullFinding, createFalsePositiveFinding } from "./findings";
import { fetchLabels, fetchFalsePositiveList } from "./utils";

let webSocket: WebSocket = new WebSocket(WEBSOCKET_URL);
const unalertedRugPullResults: RugPullResult[] = [];
const alertedFalsePositives: string[] = [];
let isWebSocketConnected: boolean;

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

export function provideInitialize(ws: WebSocket): Initialize {
  return async () => {
    setPrivateFindings(true);
    establishNewWebSocketClient(ws);
  };
}

export function provideHandleBlock(
  falsePositiveListUrl: string,
  labelFetcher: (falsePositiveEntry: FalsePositiveEntry) => Promise<Label[]>
): HandleBlock {
  return async (blockEvent: BlockEvent): Promise<Finding[]> => {
    if (!isWebSocketConnected) {
      webSocket = new WebSocket(WEBSOCKET_URL);
      establishNewWebSocketClient(webSocket);
    }

    const findings: Finding[] = [];

    if (blockEvent.blockNumber % 300 == 0) {
      const falsePositiveList: FalsePositiveEntry[] = await fetchFalsePositiveList(falsePositiveListUrl);

      await Promise.all(
        falsePositiveList.map(async (fpEntry: FalsePositiveEntry) => {
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
  initialize: provideInitialize(webSocket),
  handleBlock: provideHandleBlock(FP_CSV_PATH, fetchLabels),
  provideInitialize,
  provideHandleBlock,
};
