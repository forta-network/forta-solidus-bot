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
import { Exploit, RugPullPayload, RugPullResult, FalsePositiveEntry } from "./types";
import { createMockRugPullResults, createFetchedLabels } from "./mock.data";

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

function createRugPullFinding(rugPullResult: RugPullResult): Finding {
  const { chain_id, address, deployer_addr, name, symbol, created_at }: RugPullResult = rugPullResult;
  const resultString: string = chain_id + address + deployer_addr + name + symbol + created_at;
  const uniqueKey: string = utils.keccak256(utils.toUtf8Bytes(resultString));

  return Finding.fromObject({
    name: `Rug pull contract detected: ${rugPullResult["name"]}`,
    description: rugPullResult["exploits"][0]["name"],
    alertId: "SOLIDUS-RUG-PULL",
    severity: FindingSeverity.Critical,
    type: FindingType.Scam,
    // uniqueKey,
    // source: { chainSource: { chainId: Number(rugPullResult["chain_id"]) } },
    metadata: {
      chainId: rugPullResult["chain_id"],
      deployerAddress: rugPullResult["deployer_addr"],
      createdAddress: rugPullResult["address"],
      creationTime: rugPullResult["created_at"],
      contractName: rugPullResult["name"],
      tokenSymbol: rugPullResult["symbol"],
      exploitId: rugPullResult["exploits"][0]["id"].toString(),
      exploitName: rugPullResult["exploits"][0]["name"],
      exploitType: rugPullResult["exploits"][0]["types"],
    },
    labels: [
      Label.fromObject({
        entity: rugPullResult["address"],
        entityType: EntityType.Address,
        label: "Rug pull contract",
        confidence: 0.99,
        remove: false,
        metadata: {
          chainId: rugPullResult["chain_id"],
          contractAddress: rugPullResult["address"],
          deployerAddress: rugPullResult["deployer_addr"],
          creationTime: rugPullResult["created_at"],
          contractName: rugPullResult["name"],
          tokenSymbol: rugPullResult["symbol"],
          exploitId: rugPullResult["exploits"][0]["id"].toString(),
          exploitName: rugPullResult["exploits"][0]["name"],
          exploitType: rugPullResult["exploits"][0]["types"],
        },
      }),
      Label.fromObject({
        entity: rugPullResult["deployer_addr"],
        entityType: EntityType.Address,
        label: "Rug pull contract deployer",
        confidence: 0.99,
        remove: false,
        metadata: {
          chainId: rugPullResult["chain_id"],
          contractAddress: rugPullResult["address"],
          deployerAddress: rugPullResult["deployer_addr"],
          creationTime: rugPullResult["created_at"],
          contractName: rugPullResult["name"],
          tokenSymbol: rugPullResult["symbol"],
          exploitId: rugPullResult["exploits"][0]["id"].toString(),
          exploitName: rugPullResult["exploits"][0]["name"],
          exploitType: rugPullResult["exploits"][0]["types"],
        },
      }),
    ],
  });
}

function createFalsePositiveFinding(
  falsePositiveEntry: FalsePositiveEntry,
  labelMetadata: RugPullResult,
  labelExploit: Exploit
): Finding {
  return Finding.fromObject({
    name: `False positive rug pull contract, and its deployer, previously incorrectly labeled: ${falsePositiveEntry["contractName"]}`,
    description: `Rug pull detector previously labeled ${falsePositiveEntry["contractName"]} contract at ${falsePositiveEntry["contractAddress"]}, and its deployer ${falsePositiveEntry["deployerAddress"]}, a rug pull`,
    alertId: "SOLIDUS-RUG-PULL-FALSE-POSITIVE",
    severity: FindingSeverity.Info,
    type: FindingType.Info,
    metadata: {},
    labels: [
      Label.fromObject({
        entity: falsePositiveEntry["contractAddress"],
        entityType: EntityType.Address,
        label: "Rug pull contract",
        confidence: 0.99,
        remove: true,
        metadata: {
          chainId: labelMetadata.chain_id,
          contractAddress: labelMetadata.address,
          deployerAddress: labelMetadata.deployer_addr,
          creationTime: labelMetadata.created_at,
          contractName: labelMetadata.name,
          tokenSymbol: labelMetadata.symbol,
          exploitId: labelExploit.id.toString(),
          exploitName: labelExploit.name,
          exploitType: labelExploit.types,
        },
      }),
      Label.fromObject({
        entity: falsePositiveEntry["deployerAddress"],
        entityType: EntityType.Address,
        label: "Rug pull contract deployer",
        confidence: 0.99,
        remove: true,
        metadata: {
          chainId: labelMetadata.chain_id,
          contractAddress: labelMetadata.address,
          deployerAddress: labelMetadata.deployer_addr,
          creationTime: labelMetadata.created_at,
          contractName: labelMetadata.name,
          tokenSymbol: labelMetadata.symbol,
          exploitId: labelExploit.id.toString(),
          exploitName: labelExploit.name,
          exploitType: labelExploit.types,
        },
      }),
    ],
  });
}

describe("Rug Pull Bot Test Suite", () => {
  let mockServer: WS;
  let mockClient: WebSocket;
  const mockLabelFetcher = jest.fn();
  let handleTransaction: HandleTransaction;
  const mockTxEvent = new TestTransactionEvent().setBlock(10);
  const mockFpCsvPath: string = "./src/mock.fp.csv";

  beforeEach(async () => {
    mockServer = new WS(mockWebSocketUrl, { jsonProtocol: true });
    mockClient = await mockWebSocketCreator();
    await mockServer.connected;

    const initialize: Initialize = provideInitialize(mockWebSocketCreator);
    await initialize();

    handleTransaction = provideHandleTransaction(mockWebSocketCreator, mockFpCsvPath, mockLabelFetcher);
    const findings = await handleTransaction(mockTxEvent);
    // No alerts since no data sent from server
    expect(findings).toStrictEqual([]);
  });

  afterEach(async () => {
    WS.clean();
  });

  it("creates alerts when WebSocket server sends data", async () => {
    const mockDataThreeResults: RugPullPayload = createMockRugPullResults(3);
    mockServer.send(mockDataThreeResults);

    let findings = await handleTransaction(mockTxEvent);
    expect(findings).toStrictEqual([
      createRugPullFinding(mockDataThreeResults["result"][0]),
      createRugPullFinding(mockDataThreeResults["result"][1]),
      createRugPullFinding(mockDataThreeResults["result"][2]),
    ]);

    findings = await handleTransaction(mockTxEvent);
    // No findings since entries were cleared
    expect(findings).toStrictEqual([]);
  });

  it("creates one batch of alerts from different payloads delivered in between blocks", async () => {
    const mockDataOneResult: RugPullPayload = createMockRugPullResults(1);
    const mockDataTwoResults: RugPullPayload = createMockRugPullResults(2);

    mockServer.send(mockDataOneResult);
    mockServer.send(mockDataTwoResults);

    let findings = await handleTransaction(mockTxEvent);
    expect(findings).toStrictEqual([
      createRugPullFinding(mockDataOneResult["result"][0]),
      createRugPullFinding(mockDataTwoResults["result"][0]),
      createRugPullFinding(mockDataTwoResults["result"][1]),
    ]);

    findings = await handleTransaction(mockTxEvent);
    // No findings, since entries were cleared
    expect(findings).toStrictEqual([]);
  });

  it("creates alerts, connection closes, connection re-establishes, and bot creates more alerts", async () => {
    const spy = jest.spyOn(console, "log").mockImplementation(() => {});
    const mockDataOneResult: RugPullPayload = createMockRugPullResults(1);
    const mockDataTwoResults: RugPullPayload = createMockRugPullResults(2);

    await mockServer.send(mockDataOneResult);
    let findings = await handleTransaction(mockTxEvent);
    expect(findings).toStrictEqual([createRugPullFinding(mockDataOneResult["result"][0])]);

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

    await mockServer.send(mockDataTwoResults);
    findings = await handleTransaction(mockTxEvent);

    expect(findings).toStrictEqual([
      createRugPullFinding(mockDataTwoResults["result"][0]),
      createRugPullFinding(mockDataTwoResults["result"][1]),
    ]);
  });

  it("handles an error when received", async () => {
    const spy = jest.spyOn(console, "log").mockImplementation(() => {});
    const mockDataOneResult: RugPullPayload = createMockRugPullResults(1);

    mockServer.send(mockDataOneResult);
    let findings = await handleTransaction(mockTxEvent);
    expect(findings).toStrictEqual([createRugPullFinding(mockDataOneResult["result"][0])]);

    mockServer.error();
    expect(spy).toHaveBeenCalledWith("WebSocket connection errored out. Type: error.");
  });

  it("creates an alert for an address then creates a false positive alert for that address that was a false positive", async () => {
    const mockDataOneResult: RugPullPayload = createMockRugPullResults(1);
    when(mockLabelFetcher)
      .calledWith({
        contractName: "mockOne",
        contractAddress: createAddress("0x10"),
        chainId: "1",
        deployerAddress: createAddress("0x11"),
        comment: "Not rug pull",
      })
      .mockReturnValue(
        createFetchedLabels(
          mockDataOneResult["result"][0]["chain_id"],
          mockDataOneResult["result"][0]["address"],
          mockDataOneResult["result"][0]["deployer_addr"],
          mockDataOneResult["result"][0]["created_at"],
          mockDataOneResult["result"][0]["name"],
          mockDataOneResult["result"][0]["symbol"],
          mockDataOneResult["result"][0]["exploits"][0]["id"].toString(),
          mockDataOneResult["result"][0]["exploits"][0]["name"],
          mockDataOneResult["result"][0]["exploits"][0]["types"],
          "Rug pull contract",
          "Rug pull contract deployer"
        )
      );

    mockServer.send(mockDataOneResult);

    let findings = await handleTransaction(mockTxEvent);
    expect(findings).toStrictEqual([createRugPullFinding(mockDataOneResult["result"][0])]);

    findings = await handleTransaction(mockTxEvent);
    // No findings, since entries were cleared
    expect(findings).toStrictEqual([]);

    mockTxEvent.setBlock(300);
    findings = await handleTransaction(mockTxEvent);

    const mockFpValues: FalsePositiveEntry[] = await mockFpFetcher(mockFpCsvPath);

    expect(findings).toStrictEqual([
      createFalsePositiveFinding(
        mockFpValues[0],
        mockDataOneResult["result"][0],
        mockDataOneResult["result"][0]["exploits"][0]
      ),
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
    const mockDataSixtyFiveResults: RugPullPayload = createMockRugPullResults(65);
    mockServer.send(mockDataSixtyFiveResults);

    const firstFiftyRugPullFindings: Finding[] = [];
    mockDataSixtyFiveResults["result"].slice(0, 50).forEach((result) => {
      firstFiftyRugPullFindings.push(createRugPullFinding(result));
    });

    mockTxEvent.setBlock(10);
    let findings = await handleTransaction(mockTxEvent);
    expect(findings).toStrictEqual(firstFiftyRugPullFindings);

    const remainingFifteenRugPullFindings: Finding[] = [];
    mockDataSixtyFiveResults["result"].slice(50).forEach((result) => {
      remainingFifteenRugPullFindings.push(createRugPullFinding(result));
    });

    // Bot saved the "overflowing" 15 rug pull results
    findings = await handleTransaction(mockTxEvent);
    expect(findings).toStrictEqual(remainingFifteenRugPullFindings);

    findings = await handleTransaction(mockTxEvent);
    expect(findings).toStrictEqual([]);
  });
});
