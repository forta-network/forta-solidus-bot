import { getLabels, LabelsResponse, Label, fetchJwt } from "forta-agent";
import fetch from "node-fetch";
import fs from "fs";
import { parse, Parser } from "csv-parse";
import { finished } from "stream/promises";
import { BOT_ID, DATABASE_URL } from "./constants";
import { FalsePositiveEntry, WebSocketInfo } from "./types";

export async function fetchWebSocketInfo(): Promise<WebSocketInfo> {
  const token = await fetchJwt({});
  const headers = { Authorization: `Bearer ${token}` };
  try {
    const response = await fetch(`${DATABASE_URL}`, { headers });

    if (response.ok) {
      const webSocketInfo: WebSocketInfo = await response.json();
      return webSocketInfo;
    } else {
      return { WEBSOCKET_URL: "", WEBSOCKET_API_KEY: "" };
    }
  } catch (e) {
    console.log("Error in fetching data.");
    throw e;
  }
}

export async function fetchLabels(falsePositiveEntry: FalsePositiveEntry): Promise<Label[]> {
  const labels: Label[] = [];
  let hasNext = true;

  while (hasNext) {
    const results: LabelsResponse = await getLabels({
      entities: [falsePositiveEntry["contractAddress"], falsePositiveEntry["deployerAddress"]],
      labels: ["Scam token contract", "Scam token contract deployer"],
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

export async function fetchFalsePositiveList(csvPath: string): Promise<FalsePositiveEntry[]> {
  const records: FalsePositiveEntry[] = [];

  const parser: Parser = fs.createReadStream(csvPath).pipe(parse({ columns: true }));

  parser.on("readable", function () {
    let record: FalsePositiveEntry;
    while ((record = parser.read()) !== null) {
      records.push(record);
    }
  });

  await finished(parser);
  return records;
}
