import {
  Initialize,
  setPrivateFindings,
  HandleTransaction,
  TransactionEvent,
  Finding,
  Label,
  fetchJwt,
} from "forta-agent";
import WebSocket, { MessageEvent, ErrorEvent, CloseEvent } from "ws";
import fetch from "node-fetch";
import { MAX_RUG_PULL_RESULTS_PER_BLOCK, FP_CSV_PATH, DATABASE_URL } from "./constants";
import { RugPullResult, RugPullPayload, FalsePositiveEntry } from "./types";
import { createRugPullFinding, createFalsePositiveFinding } from "./findings";
import { fetchLabels, fetchFalsePositiveList } from "./utils";

let webSocket: WebSocket;
// Bots are allocated 1GB of memory, so storing
// `RugPullResult`s won't be an issue. Especially
// since entries will be cleared after alerted.
const unalertedRugPullResults: RugPullResult[] = [];
const alertedFalsePositives: string[] = [];
let isWebSocketConnected: boolean;

async function fetchWebSocketInfo(): Promise<string> {
  const token = await fetchJwt({});
  const headers = { Authorization: `Bearer ${token}` };
  try {
    const response = await fetch(`${DATABASE_URL}`, { headers });

    if (response.ok) {
      const data: string = await response.text();
      return data;
    } else {
      console.log(`database has no entry`);
      return "";
    }
  } catch (e) {
    console.log("Error in fetching data.");
    throw e;
  }
}

async function createNewWebSocket(): Promise<WebSocket> {
  const webSocketUrl: string = await fetchWebSocketInfo();
  return new WebSocket(webSocketUrl /*, "", { headers: { apiKey: API_KEY } }*/);
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
    console.log(`WebSocket connection errored out. Type: ${error.type}.`);
  };

  ws.onclose = (event: CloseEvent) => {
    isWebSocketConnected = false;
    console.log(`WebSocket connection closed. Code: ${event.code}. Reason (could be empty): ${event.reason}`);
  };

  isWebSocketConnected = true;
}

export function provideInitialize(webSocketCreator: () => Promise<WebSocket>): Initialize {
  return async () => {
    setPrivateFindings(true);
    webSocket = await webSocketCreator();
    await establishNewWebSocketClient(webSocket);
  };
}

export function provideHandleTransaction(
  webSocketCreator: () => Promise<WebSocket>,
  falsePositiveListUrl: string,
  labelFetcher: (falsePositiveEntry: FalsePositiveEntry) => Promise<Label[]>
): HandleTransaction {
  return async (txEvent: TransactionEvent): Promise<Finding[]> => {
    if (!isWebSocketConnected) {
      webSocket = await webSocketCreator();
      await establishNewWebSocketClient(webSocket);
    }

    const findings: Finding[] = [];

    if (txEvent.blockNumber % 300 == 0) {
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
  initialize: provideInitialize(createNewWebSocket),
  handleTransaction: provideHandleTransaction(createNewWebSocket, FP_CSV_PATH, fetchLabels),
  provideInitialize,
  provideHandleTransaction,
};
