import {
  Initialize,
  HandleBlock,
  Finding,
  FindingSeverity,
  FindingType,
  Label,
  EntityType
} from "forta-agent";
import { provideInitialize, provideHandleBlock } from "./agent";
import {
  mockDataOneResult,
  mockDataTwoResults,
  mockDataThreeResults
} from "./mock.data";
import { TestBlockEvent } from "forta-agent-tools/lib/test";
import WS from "jest-websocket-mock";
import WebSocket from 'ws';

describe("Solidus Rug Pull Bot Test Suite", () => {
  let mockServer: WS;
  let mockClient: WebSocket;
  let handleBlock: HandleBlock;
  const mockBlockEvent = new TestBlockEvent();

  beforeEach(async () => {
    mockServer = new WS("ws://localhost:1234", { jsonProtocol: true });
    mockClient = new WebSocket("ws://localhost:1234");
    await mockServer.connected;

    const initialize: Initialize = provideInitialize(mockClient);
    initialize();

    handleBlock = provideHandleBlock();
    const findings = await handleBlock(mockBlockEvent);
    // Not alerts since no data sent from server
    expect(findings).toStrictEqual([]);
  });

  afterEach(async () => {
    WS.clean();
  });

  it("creates alerts when WebSocket server sends data", async () => {
    mockServer.send(mockDataThreeResults);

    let findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual([
      Finding.fromObject({
        name: "Rug pull contract detected",
        description: mockDataThreeResults["result"][0]["exploits"][0]["name"],
        alertId: "SOLIDUS-RUG-PULL",
        severity: FindingSeverity.Critical,
        type: FindingType.Scam,
        metadata: {
          chainId: mockDataThreeResults["result"][0]["chain_id"],
          deployerAddress: mockDataThreeResults["result"][0]["deployer_addr"],
          createdAddress: mockDataThreeResults["result"][0]["address"],
          creationTime: mockDataThreeResults["result"][0]["created_at"],
          tokenName: mockDataThreeResults["result"][0]["name"],
          tokenSymbol: mockDataThreeResults["result"][0]["symbol"],
          exploitName: mockDataThreeResults["result"][0]["exploits"][0]["name"],
          exploitType: mockDataThreeResults["result"][0]["exploits"][0]["type"]
        },
        labels: [
          Label.fromObject({
            entity: mockDataThreeResults["result"][0]["address"],
            entityType: EntityType.Address,
            label: "Rug pull contract",
            confidence: 0.99,
            remove: false,
            createdAt: mockDataThreeResults["result"][0]["created_at"]
          }),
          Label.fromObject({
            entity: mockDataThreeResults["result"][0]["deployer_addr"],
            entityType: EntityType.Address,
            label: "Rug pull contract deployer",
            confidence: 0.99,
            remove: false,
          }),
        ]
      }),
      Finding.fromObject({
        name: "Rug pull contract detected",
        description: mockDataThreeResults["result"][1]["exploits"][0]["name"],
        alertId: "SOLIDUS-RUG-PULL",
        severity: FindingSeverity.Critical,
        type: FindingType.Scam,
        metadata: {
          chainId: mockDataThreeResults["result"][1]["chain_id"],
          deployerAddress: mockDataThreeResults["result"][1]["deployer_addr"],
          createdAddress: mockDataThreeResults["result"][1]["address"],
          creationTime: mockDataThreeResults["result"][1]["created_at"],
          tokenName: mockDataThreeResults["result"][1]["name"],
          tokenSymbol: mockDataThreeResults["result"][1]["symbol"],
          exploitName: mockDataThreeResults["result"][1]["exploits"][0]["name"],
          exploitType: mockDataThreeResults["result"][1]["exploits"][0]["type"]
        },
        labels: [
          Label.fromObject({
            entity: mockDataThreeResults["result"][1]["address"],
            entityType: EntityType.Address,
            label: "Rug pull contract",
            confidence: 0.99,
            remove: false,
            createdAt: mockDataThreeResults["result"][1]["created_at"]
          }),
          Label.fromObject({
            entity: mockDataThreeResults["result"][1]["deployer_addr"],
            entityType: EntityType.Address,
            label: "Rug pull contract deployer",
            confidence: 0.99,
            remove: false,
          }),
        ]
      }),
      Finding.fromObject({
        name: "Rug pull contract detected",
        description: mockDataThreeResults["result"][2]["exploits"][0]["name"],
        alertId: "SOLIDUS-RUG-PULL",
        severity: FindingSeverity.Critical,
        type: FindingType.Scam,
        metadata: {
          chainId: mockDataThreeResults["result"][2]["chain_id"],
          deployerAddress: mockDataThreeResults["result"][2]["deployer_addr"],
          createdAddress: mockDataThreeResults["result"][2]["address"],
          creationTime: mockDataThreeResults["result"][2]["created_at"],
          tokenName: mockDataThreeResults["result"][2]["name"],
          tokenSymbol: mockDataThreeResults["result"][2]["symbol"],
          exploitName: mockDataThreeResults["result"][2]["exploits"][0]["name"],
          exploitType: mockDataThreeResults["result"][2]["exploits"][0]["type"]
        },
        labels: [
          Label.fromObject({
            entity: mockDataThreeResults["result"][2]["address"],
            entityType: EntityType.Address,
            label: "Rug pull contract",
            confidence: 0.99,
            remove: false,
            createdAt: mockDataThreeResults["result"][2]["created_at"]
          }),
          Label.fromObject({
            entity: mockDataThreeResults["result"][2]["deployer_addr"],
            entityType: EntityType.Address,
            label: "Rug pull contract deployer",
            confidence: 0.99,
            remove: false,
          }),
        ]
      }),
    ]);

    findings = await handleBlock(mockBlockEvent);
    // No findings since entries were cleared
    expect(findings).toStrictEqual([]);
  });

  it("creates one batch of alerts from different payloads delivered in between blocks", async () => {
    mockServer.send(mockDataOneResult);
    mockServer.send(mockDataTwoResults);

    let findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual([
      Finding.fromObject({
        name: "Rug pull contract detected",
        description: mockDataThreeResults["result"][0]["exploits"][0]["name"],
        alertId: "SOLIDUS-RUG-PULL",
        severity: FindingSeverity.Critical,
        type: FindingType.Scam,
        metadata: {
          chainId: mockDataThreeResults["result"][0]["chain_id"],
          deployerAddress: mockDataThreeResults["result"][0]["deployer_addr"],
          createdAddress: mockDataThreeResults["result"][0]["address"],
          creationTime: mockDataThreeResults["result"][0]["created_at"],
          tokenName: mockDataThreeResults["result"][0]["name"],
          tokenSymbol: mockDataThreeResults["result"][0]["symbol"],
          exploitName: mockDataThreeResults["result"][0]["exploits"][0]["name"],
          exploitType: mockDataThreeResults["result"][0]["exploits"][0]["type"]
        },
        labels: [
          Label.fromObject({
            entity: mockDataThreeResults["result"][0]["address"],
            entityType: EntityType.Address,
            label: "Rug pull contract",
            confidence: 0.99,
            remove: false,
            createdAt: mockDataThreeResults["result"][0]["created_at"]
          }),
          Label.fromObject({
            entity: mockDataThreeResults["result"][0]["deployer_addr"],
            entityType: EntityType.Address,
            label: "Rug pull contract deployer",
            confidence: 0.99,
            remove: false,
          }),
        ]
      }),
      Finding.fromObject({
        name: "Rug pull contract detected",
        description: mockDataThreeResults["result"][1]["exploits"][0]["name"],
        alertId: "SOLIDUS-RUG-PULL",
        severity: FindingSeverity.Critical,
        type: FindingType.Scam,
        metadata: {
          chainId: mockDataThreeResults["result"][1]["chain_id"],
          deployerAddress: mockDataThreeResults["result"][1]["deployer_addr"],
          createdAddress: mockDataThreeResults["result"][1]["address"],
          creationTime: mockDataThreeResults["result"][1]["created_at"],
          tokenName: mockDataThreeResults["result"][1]["name"],
          tokenSymbol: mockDataThreeResults["result"][1]["symbol"],
          exploitName: mockDataThreeResults["result"][1]["exploits"][0]["name"],
          exploitType: mockDataThreeResults["result"][1]["exploits"][0]["type"]
        },
        labels: [
          Label.fromObject({
            entity: mockDataThreeResults["result"][1]["address"],
            entityType: EntityType.Address,
            label: "Rug pull contract",
            confidence: 0.99,
            remove: false,
            createdAt: mockDataThreeResults["result"][1]["created_at"]
          }),
          Label.fromObject({
            entity: mockDataThreeResults["result"][1]["deployer_addr"],
            entityType: EntityType.Address,
            label: "Rug pull contract deployer",
            confidence: 0.99,
            remove: false,
          }),
        ]
      }),
      Finding.fromObject({
        name: "Rug pull contract detected",
        description: mockDataThreeResults["result"][2]["exploits"][0]["name"],
        alertId: "SOLIDUS-RUG-PULL",
        severity: FindingSeverity.Critical,
        type: FindingType.Scam,
        metadata: {
          chainId: mockDataThreeResults["result"][2]["chain_id"],
          deployerAddress: mockDataThreeResults["result"][2]["deployer_addr"],
          createdAddress: mockDataThreeResults["result"][2]["address"],
          creationTime: mockDataThreeResults["result"][2]["created_at"],
          tokenName: mockDataThreeResults["result"][2]["name"],
          tokenSymbol: mockDataThreeResults["result"][2]["symbol"],
          exploitName: mockDataThreeResults["result"][2]["exploits"][0]["name"],
          exploitType: mockDataThreeResults["result"][2]["exploits"][0]["type"]
        },
        labels: [
          Label.fromObject({
            entity: mockDataThreeResults["result"][2]["address"],
            entityType: EntityType.Address,
            label: "Rug pull contract",
            confidence: 0.99,
            remove: false,
            createdAt: mockDataThreeResults["result"][2]["created_at"]
          }),
          Label.fromObject({
            entity: mockDataThreeResults["result"][2]["deployer_addr"],
            entityType: EntityType.Address,
            label: "Rug pull contract deployer",
            confidence: 0.99,
            remove: false,
          }),
        ]
      }),
    ]);

    findings = await handleBlock(mockBlockEvent);
    // No findings, since entries were cleared
    expect(findings).toStrictEqual([]);
  });

  it("creates alerts, connection closes, connection re-establishes, and bot creates more alerts", async () => {
    const spy = jest.spyOn(console, "log").mockImplementation(() => {});

    mockServer.send(mockDataOneResult);
    let findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual([
      Finding.fromObject({
        name: "Rug pull contract detected",
        description: mockDataThreeResults["result"][0]["exploits"][0]["name"],
        alertId: "SOLIDUS-RUG-PULL",
        severity: FindingSeverity.Critical,
        type: FindingType.Scam,
        metadata: {
          chainId: mockDataThreeResults["result"][0]["chain_id"],
          deployerAddress: mockDataThreeResults["result"][0]["deployer_addr"],
          createdAddress: mockDataThreeResults["result"][0]["address"],
          creationTime: mockDataThreeResults["result"][0]["created_at"],
          tokenName: mockDataThreeResults["result"][0]["name"],
          tokenSymbol: mockDataThreeResults["result"][0]["symbol"],
          exploitName: mockDataThreeResults["result"][0]["exploits"][0]["name"],
          exploitType: mockDataThreeResults["result"][0]["exploits"][0]["type"]
        },
        labels: [
          Label.fromObject({
            entity: mockDataThreeResults["result"][0]["address"],
            entityType: EntityType.Address,
            label: "Rug pull contract",
            confidence: 0.99,
            remove: false,
            createdAt: mockDataThreeResults["result"][0]["created_at"]
          }),
          Label.fromObject({
            entity: mockDataThreeResults["result"][0]["deployer_addr"],
            entityType: EntityType.Address,
            label: "Rug pull contract deployer",
            confidence: 0.99,
            remove: false,
          }),
        ]
      })
    ]);

    findings = await handleBlock(mockBlockEvent);
    // No findings, since entries were cleared
    expect(findings).toStrictEqual([]);
    mockServer.close();
    // Code `1000` since connection was closed "gracefully"
    expect(spy).toHaveBeenCalledWith("WebSocket connection closed. Code: 1000.");

    // Mocking server re-initialization
    // and re-establishing connection
    mockServer = new WS("ws://localhost:1234", { jsonProtocol: true });
    findings = await handleBlock(mockBlockEvent);
    await mockServer.connected;
    // No findings, since connection only
    // re-established and no data served
    expect(findings).toStrictEqual([]);

    mockServer.send(mockDataTwoResults);
    findings = await handleBlock(mockBlockEvent);

    expect(findings).toStrictEqual([
      Finding.fromObject({
        name: "Rug pull contract detected",
        description: mockDataThreeResults["result"][1]["exploits"][0]["name"],
        alertId: "SOLIDUS-RUG-PULL",
        severity: FindingSeverity.Critical,
        type: FindingType.Scam,
        metadata: {
          chainId: mockDataThreeResults["result"][1]["chain_id"],
          deployerAddress: mockDataThreeResults["result"][1]["deployer_addr"],
          createdAddress: mockDataThreeResults["result"][1]["address"],
          creationTime: mockDataThreeResults["result"][1]["created_at"],
          tokenName: mockDataThreeResults["result"][1]["name"],
          tokenSymbol: mockDataThreeResults["result"][1]["symbol"],
          exploitName: mockDataThreeResults["result"][1]["exploits"][0]["name"],
          exploitType: mockDataThreeResults["result"][1]["exploits"][0]["type"]
        },
        labels: [
          Label.fromObject({
            entity: mockDataThreeResults["result"][1]["address"],
            entityType: EntityType.Address,
            label: "Rug pull contract",
            confidence: 0.99,
            remove: false,
            createdAt: mockDataThreeResults["result"][1]["created_at"]
          }),
          Label.fromObject({
            entity: mockDataThreeResults["result"][1]["deployer_addr"],
            entityType: EntityType.Address,
            label: "Rug pull contract deployer",
            confidence: 0.99,
            remove: false,
          }),
        ]
      }),
      Finding.fromObject({
        name: "Rug pull contract detected",
        description: mockDataThreeResults["result"][2]["exploits"][0]["name"],
        alertId: "SOLIDUS-RUG-PULL",
        severity: FindingSeverity.Critical,
        type: FindingType.Scam,
        metadata: {
          chainId: mockDataThreeResults["result"][2]["chain_id"],
          deployerAddress: mockDataThreeResults["result"][2]["deployer_addr"],
          createdAddress: mockDataThreeResults["result"][2]["address"],
          creationTime: mockDataThreeResults["result"][2]["created_at"],
          tokenName: mockDataThreeResults["result"][2]["name"],
          tokenSymbol: mockDataThreeResults["result"][2]["symbol"],
          exploitName: mockDataThreeResults["result"][2]["exploits"][0]["name"],
          exploitType: mockDataThreeResults["result"][2]["exploits"][0]["type"]
        },
        labels: [
          Label.fromObject({
            entity: mockDataThreeResults["result"][2]["address"],
            entityType: EntityType.Address,
            label: "Rug pull contract",
            confidence: 0.99,
            remove: false,
            createdAt: mockDataThreeResults["result"][2]["created_at"]
          }),
          Label.fromObject({
            entity: mockDataThreeResults["result"][2]["deployer_addr"],
            entityType: EntityType.Address,
            label: "Rug pull contract deployer",
            confidence: 0.99,
            remove: false,
          }),
        ]
      }),
    ]);
  });

  it.skip("responds with a PONG if server sends a PING message to keep the connection alive", async () => {
    //
  });

  it("handles an error when received", async () => {
    const spy = jest.spyOn(console, "log").mockImplementation(() => {});

    mockServer.send(mockDataOneResult);
    let findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual([
      Finding.fromObject({
        name: "Rug pull contract detected",
        description: mockDataThreeResults["result"][0]["exploits"][0]["name"],
        alertId: "SOLIDUS-RUG-PULL",
        severity: FindingSeverity.Critical,
        type: FindingType.Scam,
        metadata: {
          chainId: mockDataThreeResults["result"][0]["chain_id"],
          deployerAddress: mockDataThreeResults["result"][0]["deployer_addr"],
          createdAddress: mockDataThreeResults["result"][0]["address"],
          creationTime: mockDataThreeResults["result"][0]["created_at"],
          tokenName: mockDataThreeResults["result"][0]["name"],
          tokenSymbol: mockDataThreeResults["result"][0]["symbol"],
          exploitName: mockDataThreeResults["result"][0]["exploits"][0]["name"],
          exploitType: mockDataThreeResults["result"][0]["exploits"][0]["type"]
        },
        labels: [
          Label.fromObject({
            entity: mockDataThreeResults["result"][0]["address"],
            entityType: EntityType.Address,
            label: "Rug pull contract",
            confidence: 0.99,
            remove: false,
            createdAt: mockDataThreeResults["result"][0]["created_at"]
          }),
          Label.fromObject({
            entity: mockDataThreeResults["result"][0]["deployer_addr"],
            entityType: EntityType.Address,
            label: "Rug pull contract deployer",
            confidence: 0.99,
            remove: false,
          }),
        ]
      })
    ]);

    mockServer.error();
    expect(spy).toHaveBeenCalledWith("WebSocket connection errored out. Type: error");
  });
});