import {
  Initialize,
  setPrivateFindings,
  BlockEvent,
  HandleBlock,
  Finding
} from "forta-agent";
import { createFinding } from "./findings";
import WebSocket, { MessageEvent, ErrorEvent, CloseEvent } from 'ws';

// Use `123` URL for testing
const wsUrl = "ws://localhost:1234";
// Use below for PROD
// const wsUrl = "";

// const ws: WebSocket = new WebSocket(wsUrl);
let rawRugPullData: any = [];
let isWebSocketConnected: boolean;

async function establishNewWebSocketClient(ws: WebSocket) {
  ws.onopen = (open: any) => {
    isWebSocketConnected = true;
    console.log("WebSocket connection opened.");
  };

  ws.onmessage = (message: MessageEvent) => {
    const parsedData = JSON.parse(message.data.toString());
    parsedData.result.forEach((result: any) => {
      rawRugPullData.push(result);
    });
  };

  ws.onerror = (error: ErrorEvent) => {
    isWebSocketConnected = false;
    console.log(`WebSocket connection errored out. Type: ${error.type}`);
  };

  ws.onclose = (event: CloseEvent) => {
    isWebSocketConnected = false;
    console.log(`WebSocket connection closed. Code: ${event.code}.`);
  }

  isWebSocketConnected = true;
}

export function provideInitialize(ws: WebSocket): Initialize {
  return async () => {
    setPrivateFindings(true);
    establishNewWebSocketClient(ws);
  }
};

export function provideHandleBlock(): HandleBlock {
  return async (blockEvent: BlockEvent): Promise<Finding[]> => {
    if (!isWebSocketConnected) {
      establishNewWebSocketClient(new WebSocket(wsUrl));
    }

    const findings: Finding[] = [];

    const rugPullEntries: number = rawRugPullData.length;
    if(rugPullEntries > 0) {
      rawRugPullData.forEach((entry: any) => {
        findings.push(createFinding(entry));
      });

      rawRugPullData.splice(0, rugPullEntries);
    }

    return findings;
  }
};

export default {
  // initialize: provideInitialize(ws),
  handleBlock: provideHandleBlock(),
  provideInitialize,
  provideHandleBlock,
};