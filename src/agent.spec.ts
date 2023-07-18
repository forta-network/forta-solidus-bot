import {
  HandleBlock,
  Finding,
  FindingSeverity,
  FindingType,
  Label,
  EntityType
} from "forta-agent";
import { createAddress } from "forta-agent-tools";
import { TestBlockEvent } from "forta-agent-tools/lib/test";
import WS from "jest-websocket-mock";
import { provideHandleBlock } from "./agent";
import WebSocket from 'ws';

const mockData: any = {
  "message": "OK",
  "total": 3,
  "result": [
    {
      "chain_id": "56",
      "address": createAddress("0x10"),
      "deployer_addr": createAddress("0x11"),
      "name": "mockOne",
      "symbol": "M1",
      "created_at": "2023-07-17T20:10:00.000Z",
      "exploits": [
        {
          "id": 11,
          "name": "Exploit name 01",
          "types": "Exploit type 01"
        }
      ]
    },
    {
      "chain_id": "56",
      "address": createAddress("0x20"),
      "deployer_addr": createAddress("0x21"),
      "name": "mockTwo",
      "symbol": "M2",
      "created_at": "2023-07-17T20:20:00.000Z",
      "exploits": [
        {
          "id": 22,
          "name": "Exploit name 02",
          "types": "Exploit type 02"
        }
      ]
    },
    {
      "chain_id": "56",
      "address": createAddress("0x30"),
      "deployer_addr": createAddress("0x31"),
      "name": "mockThree",
      "symbol": "M3",
      "created_at": "2023-07-17T20:30:00.000Z",
      "exploits": [
        {
          "id": 33,
          "name": "Exploit name 02",
          "types": "Exploit type 02"
        }
      ]
    }
  ]
}

describe("Solidus Rug Pull Bot Test Suite", () => {
  it("creates an alert when WebSocket delivers data", async () => {
    const mockServer: WS = new WS("ws://localhost:1234", { jsonProtocol: true });
    const mockClient: WebSocket = new WebSocket("ws://localhost:1234");
    await mockServer.connected;
    
    let handleBlock: HandleBlock = provideHandleBlock(mockClient);

    const mockBlockEvent = new TestBlockEvent();
    await handleBlock(mockBlockEvent);

    mockServer.send(mockData);

    const mockBlockEventTwo = new TestBlockEvent();
    const findings = await handleBlock(mockBlockEventTwo);

    expect(findings).toStrictEqual([
      Finding.fromObject({
        name: "Rug pull contract detected",
        description: mockData["result"][0]["exploits"][0]["name"],
        alertId: "SOLIDUS-RUG-PULL",
        severity: FindingSeverity.Critical,
        type: FindingType.Scam,
        metadata: {
          chainId: mockData["result"][0]["chain_id"],
          deployerAddress: mockData["result"][0]["deployer_addr"],
          createdAddress: mockData["result"][0]["address"],
          creationTime: mockData["result"][0]["created_at"],
          tokenName: mockData["result"][0]["name"],
          tokenSymbol: mockData["result"][0]["symbol"],
          exploitName: mockData["result"][0]["exploits"][0]["name"],
          exploitType: mockData["result"][0]["exploits"][0]["type"]
        },
        labels: [
          Label.fromObject({
            entity: mockData["result"][0]["address"],
            entityType: EntityType.Address,
            label: "Rug pull contract",
            confidence: 0.99,
            remove: false,
            createdAt: mockData["result"][0]["created_at"]
          }),
          Label.fromObject({
            entity: mockData["result"][0]["deployer_addr"],
            entityType: EntityType.Address,
            label: "Rug pull contract deployer",
            confidence: 0.99,
            remove: false,
          }),
        ]
      }),
      Finding.fromObject({
        name: "Rug pull contract detected",
        description: mockData["result"][1]["exploits"][0]["name"],
        alertId: "SOLIDUS-RUG-PULL",
        severity: FindingSeverity.Critical,
        type: FindingType.Scam,
        metadata: {
          chainId: mockData["result"][1]["chain_id"],
          deployerAddress: mockData["result"][1]["deployer_addr"],
          createdAddress: mockData["result"][1]["address"],
          creationTime: mockData["result"][1]["created_at"],
          tokenName: mockData["result"][1]["name"],
          tokenSymbol: mockData["result"][1]["symbol"],
          exploitName: mockData["result"][1]["exploits"][0]["name"],
          exploitType: mockData["result"][1]["exploits"][0]["type"]
        },
        labels: [
          Label.fromObject({
            entity: mockData["result"][1]["address"],
            entityType: EntityType.Address,
            label: "Rug pull contract",
            confidence: 0.99,
            remove: false,
            createdAt: mockData["result"][1]["created_at"]
          }),
          Label.fromObject({
            entity: mockData["result"][1]["deployer_addr"],
            entityType: EntityType.Address,
            label: "Rug pull contract deployer",
            confidence: 0.99,
            remove: false,
          }),
        ]
      }),
      Finding.fromObject({
        name: "Rug pull contract detected",
        description: mockData["result"][2]["exploits"][0]["name"],
        alertId: "SOLIDUS-RUG-PULL",
        severity: FindingSeverity.Critical,
        type: FindingType.Scam,
        metadata: {
          chainId: mockData["result"][2]["chain_id"],
          deployerAddress: mockData["result"][2]["deployer_addr"],
          createdAddress: mockData["result"][2]["address"],
          creationTime: mockData["result"][2]["created_at"],
          tokenName: mockData["result"][2]["name"],
          tokenSymbol: mockData["result"][2]["symbol"],
          exploitName: mockData["result"][2]["exploits"][0]["name"],
          exploitType: mockData["result"][2]["exploits"][0]["type"]
        },
        labels: [
          Label.fromObject({
            entity: mockData["result"][2]["address"],
            entityType: EntityType.Address,
            label: "Rug pull contract",
            confidence: 0.99,
            remove: false,
            createdAt: mockData["result"][2]["created_at"]
          }),
          Label.fromObject({
            entity: mockData["result"][2]["deployer_addr"],
            entityType: EntityType.Address,
            label: "Rug pull contract deployer",
            confidence: 0.99,
            remove: false,
          }),
        ]
      }),
    ]);

    WS.clean();
  })
});