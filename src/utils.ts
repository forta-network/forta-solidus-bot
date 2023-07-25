import { getLabels, LabelsResponse, Label } from "forta-agent";
import fs from "fs";
import { parse, Parser } from "csv-parse";
import { finished } from "stream/promises";
import { BOT_ID } from "./constants";
import { FalsePositiveEntry } from "./types";

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
