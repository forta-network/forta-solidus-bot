import { Initialize, setPrivateFindings, HandleTransaction, TransactionEvent, Finding, Label } from "forta-agent";
import WebSocket, { MessageEvent, ErrorEvent, CloseEvent } from "ws";
import { MAX_SCAM_TOKEN_RESULTS_PER_BLOCK, FP_CSV_PATH } from "./constants";
import { ScamTokenResult, FalsePositiveEntry } from "./types";
import { createScamTokenFinding, createFalsePositiveFinding } from "./findings";
import { fetchWebSocketInfo, fetchLabels, fetchFalsePositiveList } from "./utils";

const WEBSOCKET_URL: string = "";
const API_KEY: string = "";

let webSocket: WebSocket;
// Bots are allocated 1GB of memory, so storing
// `ScamTokenResult`s won't be an issue. Especially
// since entries will be cleared after alerted.
const unalertedScamTokenResults: ScamTokenResult[] = [];
const alertedFalsePositives: string[] = [];
let isWebSocketConnected: boolean;

async function createNewWebSocket(): Promise<WebSocket> {
  // const webSocketUrl: string = await fetchWebSocketInfo();
  return new WebSocket(WEBSOCKET_URL, { headers: { apiKey: API_KEY } });
}

async function establishNewWebSocketClient(ws: WebSocket) {
  ws.onopen = () => {
    isWebSocketConnected = true;
    console.log("WebSocket connection opened.");
  };

  ws.onmessage = (message: MessageEvent) => {
    const parsedData = JSON.parse(message.data.toString().replace(/'/g, '"'));

    if (parsedData["status"] === 200) {
      isWebSocketConnected = true;
    } else if (parsedData["status"] === 401) {
      console.log(`Authentication failed: ${message.data}`);
      isWebSocketConnected = false;
    } else if (parsedData["chain_id"]) {
      const newScamTokemEntry: ScamTokenResult = parsedData;
      unalertedScamTokenResults.push(newScamTokemEntry);
    } else {
      console.log(`Unexpected response: ${message.data}`);
      isWebSocketConnected = false;
    }
  };

  ws.onerror = (error: ErrorEvent) => {
    isWebSocketConnected = false;
    console.log(`WebSocket connection errored out. Type: ${error.type}.`);
  };

  ws.onclose = (event: CloseEvent) => {
    isWebSocketConnected = false;
    console.log(`WebSocket connection closed. Code: ${event.code}. Reason (could be empty): ${event.reason}`);
  };

  console.log("WebSocket connection established.");
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

    const resultsToBeProcessed: ScamTokenResult[] = unalertedScamTokenResults.splice(
      0,
      Math.min(unalertedScamTokenResults.length, MAX_SCAM_TOKEN_RESULTS_PER_BLOCK)
    );
    findings.push(...resultsToBeProcessed.map(createScamTokenFinding));

    return findings;
  };
}

export default {
  initialize: provideInitialize(createNewWebSocket),
  handleTransaction: provideHandleTransaction(createNewWebSocket, FP_CSV_PATH, fetchLabels),
  provideInitialize,
  provideHandleTransaction,
};
