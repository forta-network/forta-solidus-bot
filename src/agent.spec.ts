import { Initialize, HandleBlock, Finding, FindingSeverity, FindingType, Label, EntityType } from "forta-agent";
import { TestBlockEvent } from "forta-agent-tools/lib/test";
import { when } from "jest-when";
import WS from "jest-websocket-mock";
import WebSocket from "ws";
import { provideInitialize, provideHandleBlock } from "./agent";
import { RugPullPayload, RugPullResult, FalsePositiveInfo } from "./types";
import { createMockRugPullResults, mockFpDb, createFetchedLabels } from "./mock.data";

function createRugPullFinding(rugPullResult: RugPullResult): Finding {
  return Finding.fromObject({
    name: `Rug pull contract detected: ${rugPullResult["name"]}`,
    description: rugPullResult["exploits"][0]["name"],
    alertId: "SOLIDUS-RUG-PULL",
    severity: FindingSeverity.Critical,
    type: FindingType.Scam,
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

function createContractFalsePositiveFinding(
  falsePositiveEntry: FalsePositiveInfo,
  chainId: string,
  contractAddress: string,
  deployerAddress: string,
  creationTime: string,
  contractName: string,
  tokenSymbol: string,
  exploitId: string,
  exploitName: string,
  exploitType: string
): Finding {
  return Finding.fromObject({
    name: `False positive rug pull contract previously incorrectly labeled: ${falsePositiveEntry["contractName"]}`,
    description: `Rug pull detector previously labeled ${falsePositiveEntry["contractName"]} contract at ${falsePositiveEntry["contractAddress"]} a rug pull`,
    alertId: "SOLIDUS-RUG-PULL-FALSE-POSITIVE-CONTRACT",
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
          chainId,
          contractAddress,
          deployerAddress,
          creationTime,
          contractName,
          tokenSymbol,
          exploitId,
          exploitName,
          exploitType,
        },
      }),
    ],
  });
}

function createDeployerFalsePositiveFinding(
  falsePositiveEntry: FalsePositiveInfo,
  chainId: string,
  contractAddress: string,
  deployerAddress: string,
  creationTime: string,
  contractName: string,
  tokenSymbol: string,
  exploitId: string,
  exploitName: string,
  exploitType: string
): Finding {
  return Finding.fromObject({
    name: "False positive rug pull contract deployer previously incorrectly labeled",
    description: `Rug pull detector previously labeled ${falsePositiveEntry["deployerAddress"]} a rug pull deployer`,
    alertId: "SOLIDUS-RUG-PULL-FALSE-POSITIVE-DEPLOYER",
    severity: FindingSeverity.Info,
    type: FindingType.Info,
    metadata: {},
    labels: [
      Label.fromObject({
        entity: falsePositiveEntry["deployerAddress"],
        entityType: EntityType.Address,
        label: "Rug pull contract deployer",
        confidence: 0.99,
        remove: true,
        metadata: {
          chainId,
          contractAddress,
          deployerAddress,
          creationTime,
          contractName,
          tokenSymbol,
          exploitId,
          exploitName,
          exploitType,
        },
      }),
    ],
  });
}

describe("Solidus Rug Pull Bot Test Suite", () => {
  let mockServer: WS;
  let mockClient: WebSocket;
  const mockFpFetcher = jest.fn();
  const mockLabelFetcher = jest.fn();
  let handleBlock: HandleBlock;
  const mockBlockEvent = new TestBlockEvent().setNumber(10);

  beforeEach(async () => {
    mockServer = new WS("ws://localhost:1234", { jsonProtocol: true });
    mockClient = new WebSocket("ws://localhost:1234");
    await mockServer.connected;

    mockFpFetcher.mockReturnValue(mockFpDb);

    const initialize: Initialize = provideInitialize(mockClient);
    await initialize();

    handleBlock = provideHandleBlock("testFpURL", mockFpFetcher, mockLabelFetcher);
    const findings = await handleBlock(mockBlockEvent);
    // No alerts since no data sent from server
    expect(findings).toStrictEqual([]);
  });

  afterEach(async () => {
    WS.clean();
  });

  it("creates alerts when WebSocket server sends data", async () => {
    const mockDataThreeResults: RugPullPayload = createMockRugPullResults(3);
    mockServer.send(mockDataThreeResults);

    let findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual([
      createRugPullFinding(mockDataThreeResults["result"][0]),
      createRugPullFinding(mockDataThreeResults["result"][1]),
      createRugPullFinding(mockDataThreeResults["result"][2]),
    ]);

    findings = await handleBlock(mockBlockEvent);
    // No findings since entries were cleared
    expect(findings).toStrictEqual([]);
  });

  it("creates one batch of alerts from different payloads delivered in between blocks", async () => {
    const mockDataOneResult: RugPullPayload = createMockRugPullResults(1);
    const mockDataTwoResults: RugPullPayload = createMockRugPullResults(2);

    mockServer.send(mockDataOneResult);
    mockServer.send(mockDataTwoResults);

    let findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual([
      createRugPullFinding(mockDataOneResult["result"][0]),
      createRugPullFinding(mockDataTwoResults["result"][0]),
      createRugPullFinding(mockDataTwoResults["result"][1]),
    ]);

    findings = await handleBlock(mockBlockEvent);
    // No findings, since entries were cleared
    expect(findings).toStrictEqual([]);
  });

  it("creates alerts, connection closes, connection re-establishes, and bot creates more alerts", async () => {
    const spy = jest.spyOn(console, "log").mockImplementation(() => {});
    const mockDataOneResult: RugPullPayload = createMockRugPullResults(1);
    const mockDataTwoResults: RugPullPayload = createMockRugPullResults(2);

    mockServer.send(mockDataOneResult);
    let findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual([createRugPullFinding(mockDataOneResult["result"][0])]);

    findings = await handleBlock(mockBlockEvent);
    // No findings, since entries were cleared
    expect(findings).toStrictEqual([]);
    mockServer.close();
    // Code `1000` since connection was closed "gracefully"
    expect(spy).toHaveBeenCalledWith("WebSocket connection closed. Code: 1000. Reason (could be empty): ");

    // Mocking server re-initialization
    // and re-establishing connection
    mockServer = new WS("ws://localhost:1234", { jsonProtocol: true });
    findings = await handleBlock(mockBlockEvent);
    // No findings, since connection only
    // re-established and no data served
    expect(findings).toStrictEqual([]);

    mockServer.send(mockDataTwoResults);
    findings = await handleBlock(mockBlockEvent);

    expect(findings).toStrictEqual([
      createRugPullFinding(mockDataTwoResults["result"][0]),
      createRugPullFinding(mockDataTwoResults["result"][1]),
    ]);
  });

  it("handles an error when received", async () => {
    const spy = jest.spyOn(console, "log").mockImplementation(() => {});
    const mockDataOneResult: RugPullPayload = createMockRugPullResults(1);

    mockServer.send(mockDataOneResult);
    let findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual([createRugPullFinding(mockDataOneResult["result"][0])]);

    mockServer.error();
    expect(spy).toHaveBeenCalledWith("WebSocket connection errored out. Type: error.");
  });

  it("creates an alert for an address then creates a false positive alert for that address that was a false positive", async () => {
    const mockDataOneResult: RugPullPayload = createMockRugPullResults(1);
    when(mockLabelFetcher)
      .calledWith(mockDataOneResult["result"][0]["address"], "Rug pull contract")
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
          "Rug pull contract"
        )
      )
      .calledWith(mockDataOneResult["result"][0]["deployer_addr"], "Rug pull contract deployer")
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
          "Rug pull contract deployer"
        )
      );

    mockServer.send(mockDataOneResult);

    let findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual([createRugPullFinding(mockDataOneResult["result"][0])]);

    findings = await handleBlock(mockBlockEvent);
    // No findings, since entries were cleared
    expect(findings).toStrictEqual([]);

    mockBlockEvent.setNumber(300);
    findings = await handleBlock(mockBlockEvent);

    console.log(`findings in test: ${JSON.stringify(findings)}`);

    const mockFpValues: FalsePositiveInfo[] = Object.values(mockFpDb);
    expect(findings).toStrictEqual([
      createContractFalsePositiveFinding(
        mockFpValues[0],
        mockDataOneResult["result"][0]["chain_id"],
        mockDataOneResult["result"][0]["address"],
        mockDataOneResult["result"][0]["deployer_addr"],
        mockDataOneResult["result"][0]["created_at"],
        mockDataOneResult["result"][0]["name"],
        mockDataOneResult["result"][0]["symbol"],
        mockDataOneResult["result"][0]["exploits"][0]["id"].toString(),
        mockDataOneResult["result"][0]["exploits"][0]["name"],
        mockDataOneResult["result"][0]["exploits"][0]["types"]
      ),
      createDeployerFalsePositiveFinding(
        mockFpValues[0],
        mockDataOneResult["result"][0]["chain_id"],
        mockDataOneResult["result"][0]["address"],
        mockDataOneResult["result"][0]["deployer_addr"],
        mockDataOneResult["result"][0]["created_at"],
        mockDataOneResult["result"][0]["name"],
        mockDataOneResult["result"][0]["symbol"],
        mockDataOneResult["result"][0]["exploits"][0]["id"].toString(),
        mockDataOneResult["result"][0]["exploits"][0]["name"],
        mockDataOneResult["result"][0]["exploits"][0]["types"]
      ),
    ]);

    mockBlockEvent.setNumber(600);
    findings = await handleBlock(mockBlockEvent);
    // FP Finding should not be created for
    // previous fetched Label
    expect(findings).toStrictEqual([]);
  });

  it("creates alerts up to the 50 alert limit then creates the rest in the subsequent block", async () => {
    const mockDataSixtyFiveResults: RugPullPayload = createMockRugPullResults(65);
    mockServer.send(mockDataSixtyFiveResults);

    const firstFiftyRugPullFindings: Finding[] = [];
    mockDataSixtyFiveResults["result"].slice(0, 50).forEach((result) => {
      firstFiftyRugPullFindings.push(createRugPullFinding(result));
    });

    let findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual(firstFiftyRugPullFindings);

    const remainingFifteenRugPullFindings: Finding[] = [];
    mockDataSixtyFiveResults["result"].slice(50).forEach((result) => {
      remainingFifteenRugPullFindings.push(createRugPullFinding(result));
    });

    // Bot saved the "overflowing" 15 rug pull results
    findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual(remainingFifteenRugPullFindings);

    findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual([]);
  });
});
