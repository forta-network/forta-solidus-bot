import { getLabels, LabelsResponse, Label, fetchJwt } from "forta-agent";
import fetch from "node-fetch";
import fs from "fs";
import { parse, Parser } from "csv-parse";
import { finished } from "stream/promises";
import axios from "axios";
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

// TODO: Implement logic to fetch from private repo
export async function fetchFalsePositiveList(
  falsePositiveListUrl: string,
  localFalsePositivePath: string
): Promise<FalsePositiveEntry[]> {
  const retryCount = 3;
  const records: FalsePositiveEntry[] = [];

  let parser: Parser;

  for (let i = 0; i <= retryCount; i++) {
    try {
      parser = parse((await axios.get(falsePositiveListUrl)).data, { columns: true });

      parser.on("readable", function () {
        let record: FalsePositiveEntry;
        while ((record = parser.read()) !== null) {
          records.push(record);
        }
      });

      await finished(parser);
      break;
    } catch (e) {
      try {
        parser = fs.createReadStream(localFalsePositivePath).pipe(parse({ columns: true }));

        parser.on("readable", function () {
          let record: FalsePositiveEntry;
          while ((record = parser.read()) !== null) {
            records.push(record);
          }
        });

        await finished(parser);
        break;
      } catch (e) {
        if (i === retryCount) {
          console.log("Error fetching false positive list.");
        }
      }
    }
  }

  return records;
}
