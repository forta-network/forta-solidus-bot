import {
  Initialize,
  setPrivateFindings,
  BlockEvent,
  HandleBlock,
  Finding
} from "forta-agent";
import {
  createFinding,
  createFalsePositiveFinding
} from "./findings";
import WebSocket, { MessageEvent, ErrorEvent, CloseEvent } from 'ws';
import axios from "axios";

// Use `123` URL for testing
const wsUrl = "ws://localhost:1234";
// Use below for PROD
// const wsUrl = "";
const fpUrl = "";

// const ws: WebSocket = new WebSocket(wsUrl);
let rawRugPullData: any = [];
let isWebSocketConnected: boolean;
let alertedFalsePositives: any = [];

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

async function getFpList(url: string) {
  return (await axios.get(url)).data;
}

export function provideInitialize(ws: WebSocket): Initialize {
  return async () => {
    setPrivateFindings(true);
    establishNewWebSocketClient(ws);
  }
};

export function provideHandleBlock(fpUrl: string, fpFetcher: any): HandleBlock {
  return async (blockEvent: BlockEvent): Promise<Finding[]> => {
    if (!isWebSocketConnected) {
      establishNewWebSocketClient(new WebSocket(wsUrl));
    }

    const findings: Finding[] = [];

    if(blockEvent.blockNumber % 300 == 0) {
      const fpList = await fpFetcher(fpUrl);

      Object.entries(fpList).forEach((fp) => {
        if(!alertedFalsePositives.includes(fp[0])) {
          findings.push(createFalsePositiveFinding(fp));
          alertedFalsePositives.push(fp[0]);
        }
      });
    }

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
  // handleBlock: provideHandleBlock(fpUrl, getFpList),
  provideInitialize,
  provideHandleBlock,
};