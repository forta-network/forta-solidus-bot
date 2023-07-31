import { getLabels, LabelsResponse, Label, fetchJwt } from "forta-agent";
import fetch from "node-fetch";
import fs from "fs";
import { parse, Parser } from "csv-parse";
import { finished } from "stream/promises";
import { BOT_ID, DATABASE_URL } from "./constants";
import { FalsePositiveEntry } from "./types";

export async function fetchWebSocketInfo(): Promise<string> {
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

export async function fetchLabels(falsePositiveEntry: FalsePositiveEntry): Promise<Label[]> {
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
