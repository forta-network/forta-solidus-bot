import {
    getLabels,
    LabelsResponse,
    Label
} from "forta-agent";
import axios from "axios";
import { BOT_ID } from "./constants";
import { FalsePositiveInfo, FalsePositiveDatabase } from "./types";

export async function fetchLabels(falsePositiveEntry: FalsePositiveInfo): Promise<Label[]> {
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

export async function fetchFalsePositiveList(falsePositiveDbUrl: string): Promise<FalsePositiveDatabase> {
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