import { Initialize, HandleTransaction, Finding, FindingSeverity, FindingType, Label, EntityType } from "forta-agent";
import { createAddress } from "forta-agent-tools";
import { TestTransactionEvent } from "forta-agent-tools/lib/test";
import { when } from "jest-when";
import WebSocket from "ws";
import WS from "jest-websocket-mock";
import fs from "fs";
import { parse, Parser } from "csv-parse";
import { finished } from "stream/promises";
import { utils } from "ethers";
import { provideInitialize, provideHandleTransaction } from "./agent";
import { Exploit, ScamTokenResult, FalsePositiveEntry } from "./types";
import { createMockScamTokenResults, createFetchedLabels } from "./mock.data";

const mockWebSocketUrl: string = "ws://localhost:1234";

async function mockWebSocketCreator(): Promise<WebSocket> {
  return new WebSocket(mockWebSocketUrl);
}

async function mockFpFetcher(csvPath: string): Promise<FalsePositiveEntry[]> {
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

function createScamTokenFinding(scamTokenResult: ScamTokenResult): Finding {
  const { chain_id, address, deployer_addr, name, symbol, created_at, exploits }: ScamTokenResult = scamTokenResult;
  const { id: exploit_id, name: exploit_name, types: exploit_type }: Exploit = exploits[0];
  const resultString: string = chain_id + address + deployer_addr + name + symbol + created_at;
  const uniqueKey: string = utils.keccak256(utils.toUtf8Bytes(resultString));

  return Finding.fromObject({
    name: `Scam token contract detected: ${name}`,
    description: exploit_name,
    alertId: "SCAM-TOKEN-NEW",
    severity: FindingSeverity.Critical,
    type: FindingType.Scam,
    uniqueKey,
    source: { chainSource: { chainId: Number(chain_id) } },
    addresses: [address, deployer_addr],
    protocol: name,
    metadata: {
      chain_id,
      deployer_addr,
      address,
      created_at,
      name,
      symbol,
      exploit_id: exploit_id.toString(),
      exploit_name,
      exploit_type,
    },
    labels: [
      Label.fromObject({
        entity: address,
        entityType: EntityType.Address,
        label: "Scam token contract",
        confidence: 0.99,
        remove: false,
        metadata: {
          chain_id,
          address,
          deployer_addr,
          created_at,
          name,
          symbol,
          exploit_id: exploit_id.toString(),
          exploit_name,
          exploit_type,
        },
      }),
      Label.fromObject({
        entity: deployer_addr,
        entityType: EntityType.Address,
        label: "Scam token contract deployer",
        confidence: 0.99,
        remove: false,
        metadata: {
          chain_id,
          address,
          deployer_addr,
          created_at,
          name,
          symbol,
          exploit_id: exploit_id.toString(),
          exploit_name,
          exploit_type,
        },
      }),
    ],
  });
}

function createFalsePositiveFinding(
  falsePositiveEntry: FalsePositiveEntry,
  labelMetadata: ScamTokenResult,
  labelExploit: Exploit
): Finding {
  const { chain_id, address, deployer_addr, name, symbol, created_at }: ScamTokenResult = labelMetadata;
  const { id: exploit_id, name: exploit_name, types: exploit_type }: Exploit = labelExploit;
  // Exclude `creationTime` from `resultString` to
  // not create exact same `uniqueKey` as other Finding
  const resultString: string = chain_id + address + deployer_addr + name + symbol;
  const uniqueKey: string = utils.keccak256(utils.toUtf8Bytes(resultString));

  return Finding.fromObject({
    name: `False positive scam token contract, and its deployer, previously incorrectly labeled: ${falsePositiveEntry["contractName"]}`,
    description: `Scam token detector previously labeled ${falsePositiveEntry["contractName"]} contract at ${falsePositiveEntry["contractAddress"]}, and its deployer ${falsePositiveEntry["deployerAddress"]}, a scam token`,
    alertId: "SCAM-TOKEN-FALSE-POSITIVE",
    severity: FindingSeverity.Info,
    type: FindingType.Info,
    uniqueKey,
    source: { chainSource: { chainId: Number(chain_id) } },
    metadata: {},
    labels: [
      Label.fromObject({
        entity: falsePositiveEntry["contractAddress"],
        entityType: EntityType.Address,
        label: "Scam token contract",
        confidence: 0.99,
        remove: true,
        metadata: {
          chain_id,
          address,
          deployer_addr,
          created_at,
          name,
          symbol,
          exploit_id: exploit_id.toString(),
          exploit_name,
          exploit_type,
        },
      }),
      Label.fromObject({
        entity: falsePositiveEntry["deployerAddress"],
        entityType: EntityType.Address,
        label: "Scam token contract deployer",
        confidence: 0.99,
        remove: true,
        metadata: {
          chain_id,
          address,
          deployer_addr,
          created_at,
          name,
          symbol,
          exploit_id: exploit_id.toString(),
          exploit_name,
          exploit_type,
        },
      }),
    ],
  });
}

describe("Scam Token Bot Test Suite", () => {
  let mockServer: WS;
  const mockLabelFetcher = jest.fn();
  let handleTransaction: HandleTransaction;
  const mockTxEvent = new TestTransactionEvent().setBlock(10);
  const mockFpCsvGithubUrl: string = "mock/url/false.positives.csv";
  const mockFpCsvPath: string = "./src/mock.fp.csv";

  beforeEach(async () => {
    mockServer = new WS(mockWebSocketUrl, { jsonProtocol: true });
    await mockWebSocketCreator();
    await mockServer.connected;

    const initialize: Initialize = provideInitialize(mockWebSocketCreator);
    await initialize();

    handleTransaction = provideHandleTransaction(mockWebSocketCreator, mockFpCsvGithubUrl, mockFpCsvPath, mockLabelFetcher);
    const findings = await handleTransaction(mockTxEvent);
    // No alerts since no data sent from server
    expect(findings).toStrictEqual([]);
  });

  afterEach(async () => {
    WS.clean();
  });

  it("creates alerts when WebSocket server sends data", async () => {
    const mockDataThreeResults: ScamTokenResult[] = createMockScamTokenResults(3);

    mockDataThreeResults.forEach((result: ScamTokenResult) => {
      mockServer.send(result);
    });

    let findings = await handleTransaction(mockTxEvent);
    expect(findings).toStrictEqual([
      createScamTokenFinding(mockDataThreeResults[0]),
      createScamTokenFinding(mockDataThreeResults[1]),
      createScamTokenFinding(mockDataThreeResults[2]),
    ]);

    findings = await handleTransaction(mockTxEvent);
    // No findings since entries were cleared
    expect(findings).toStrictEqual([]);
  });

  it("creates different batches of alerts in different transactions from different payloads delivered seperately", async () => {
    const mockDataOneResult: ScamTokenResult[] = createMockScamTokenResults(1);
    const mockDataTwoResults: ScamTokenResult[] = createMockScamTokenResults(2);

    mockDataOneResult.forEach((result: ScamTokenResult) => {
      mockServer.send(result);
    });

    let findings = await handleTransaction(mockTxEvent);
    expect(findings).toStrictEqual([createScamTokenFinding(mockDataOneResult[0])]);

    findings = await handleTransaction(mockTxEvent);
    // No findings, since entries were cleared
    expect(findings).toStrictEqual([]);

    mockDataTwoResults.forEach((result: ScamTokenResult) => {
      mockServer.send(result);
    });

    findings = await handleTransaction(mockTxEvent);
    expect(findings).toStrictEqual([
      createScamTokenFinding(mockDataTwoResults[0]),
      createScamTokenFinding(mockDataTwoResults[1]),
    ]);
  });

  it("creates alerts, connection closes, connection re-establishes, and bot creates more alerts", async () => {
    const spy = jest.spyOn(console, "log").mockImplementation(() => {});
    const mockDataOneResult: ScamTokenResult[] = createMockScamTokenResults(1);
    const mockDataTwoResults: ScamTokenResult[] = createMockScamTokenResults(2);

    mockDataOneResult.forEach((result: ScamTokenResult) => {
      mockServer.send(result);
    });

    let findings = await handleTransaction(mockTxEvent);
    expect(findings).toStrictEqual([createScamTokenFinding(mockDataOneResult[0])]);

    findings = await handleTransaction(mockTxEvent);
    // No findings, since entries were cleared
    expect(findings).toStrictEqual([]);
    await mockServer.close();
    // Code `1000` since connection was closed "gracefully"
    expect(spy).toHaveBeenCalledWith("WebSocket connection closed. Code: 1000. Reason (could be empty): ");

    // Mocking server re-initialization
    // and re-establishing connection
    mockServer = new WS(mockWebSocketUrl, { jsonProtocol: true });
    findings = await handleTransaction(mockTxEvent);
    // No findings, since connection only
    // re-established and no data served
    expect(findings).toStrictEqual([]);

    mockDataTwoResults.forEach((result: ScamTokenResult) => {
      mockServer.send(result);
    });

    findings = await handleTransaction(mockTxEvent);

    expect(findings).toStrictEqual([
      createScamTokenFinding(mockDataTwoResults[0]),
      createScamTokenFinding(mockDataTwoResults[1]),
    ]);
  });

  it("handles an error when received", async () => {
    const spy = jest.spyOn(console, "log").mockImplementation(() => {});
    const mockDataOneResult: ScamTokenResult[] = createMockScamTokenResults(1);

    mockDataOneResult.forEach((result: ScamTokenResult) => {
      mockServer.send(result);
    });

    let findings = await handleTransaction(mockTxEvent);
    expect(findings).toStrictEqual([createScamTokenFinding(mockDataOneResult[0])]);

    mockServer.error();
    expect(spy).toHaveBeenCalledWith("WebSocket connection errored out. Type: error.");
  });

  it("creates an alert for an address then creates a false positive alert for that address that was a false positive", async () => {
    const mockDataOneResult: ScamTokenResult[] = createMockScamTokenResults(1);

    when(mockLabelFetcher)
      .calledWith({
        contractName: "mockOne",
        contractAddress: createAddress("0x10"),
        chainId: "1",
        deployerAddress: createAddress("0x11"),
        comment: "Not scam token",
      })
      .mockReturnValue(
        createFetchedLabels(
          mockDataOneResult[0]["chain_id"],
          mockDataOneResult[0]["address"],
          mockDataOneResult[0]["deployer_addr"],
          mockDataOneResult[0]["created_at"],
          mockDataOneResult[0]["name"],
          mockDataOneResult[0]["symbol"],
          mockDataOneResult[0]["exploits"][0]["id"].toString(),
          mockDataOneResult[0]["exploits"][0]["name"],
          mockDataOneResult[0]["exploits"][0]["types"],
          "Scam token contract",
          "Scam token contract deployer"
        )
      );

    mockDataOneResult.forEach((result: ScamTokenResult) => {
      mockServer.send(result);
    });

    let findings = await handleTransaction(mockTxEvent);
    expect(findings).toStrictEqual([createScamTokenFinding(mockDataOneResult[0])]);

    findings = await handleTransaction(mockTxEvent);
    // No findings, since entries were cleared
    expect(findings).toStrictEqual([]);

    mockTxEvent.setBlock(300);
    findings = await handleTransaction(mockTxEvent);

    const mockFpValues: FalsePositiveEntry[] = await mockFpFetcher(mockFpCsvPath);

    expect(findings).toStrictEqual([
      createFalsePositiveFinding(mockFpValues[0], mockDataOneResult[0], mockDataOneResult[0]["exploits"][0]),
    ]);

    mockTxEvent.setBlock(600);
    findings = await handleTransaction(mockTxEvent);
    // FP Finding should not be created for
    // previous fetched Label
    expect(findings).toStrictEqual([]);
  });

  // There is a limit of 250KB for pushed findings,
  // but that would be more than 50 findings.
  // Therefore, this test indirectly tests to confirm
  // we aren't attempting to push more than
  // 250 KB worth of findings either.
  it("creates alerts up to the 50 alert limit then creates the rest in the subsequent block", async () => {
    const mockDataSixtyFiveResults: ScamTokenResult[] = createMockScamTokenResults(65);

    mockDataSixtyFiveResults.forEach((result: ScamTokenResult) => {
      mockServer.send(result);
    });

    const firstFiftyScamTokenFindings: Finding[] = [];
    mockDataSixtyFiveResults.slice(0, 50).forEach((result: ScamTokenResult) => {
      firstFiftyScamTokenFindings.push(createScamTokenFinding(result));
    });

    mockTxEvent.setBlock(10);
    let findings = await handleTransaction(mockTxEvent);
    expect(findings).toStrictEqual(firstFiftyScamTokenFindings);

    const remainingFifteenScamTokenFindings: Finding[] = [];
    mockDataSixtyFiveResults.slice(50).forEach((result: ScamTokenResult) => {
      remainingFifteenScamTokenFindings.push(createScamTokenFinding(result));
    });

    // Bot saved the "overflowing" 15 scam token results
    findings = await handleTransaction(mockTxEvent);
    expect(findings).toStrictEqual(remainingFifteenScamTokenFindings);

    findings = await handleTransaction(mockTxEvent);
    expect(findings).toStrictEqual([]);
  });
});
