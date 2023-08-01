import { fetchFalsePositiveList, fetchWebSocketInfo } from "./utils";
import { FalsePositiveEntry, WebSocketInfo } from "./types";
import { mockWebSocketInfo } from "./mock.data";
import fetch, { Response } from "node-fetch";

jest.mock("node-fetch");

const mockJwt = "MOCK_JWT";

// Mock the fetchJwt function of the forta-agent module
const mockFetchJwt = jest.fn();
jest.mock("forta-agent", () => {
  const original = jest.requireActual("forta-agent");
  return {
    ...original,
    fetchJwt: () => mockFetchJwt(),
  };
});

describe("Scam Token Bot Utils Test Suite", () => {
  const mockFpCsvPath: string = "./src/mock.fp.csv";
  let mockFetch = jest.mocked(fetch, true);

  it("confirms fetchFalsePositiveList works as expected", async () => {
    const fpEntries: FalsePositiveEntry[] = await fetchFalsePositiveList(mockFpCsvPath);

    expect(fpEntries).toStrictEqual([
      {
        contractName: "mockOne",
        contractAddress: "0x0000000000000000000000000000000000000010",
        deployerAddress: "0x0000000000000000000000000000000000000011",
        chainId: "1",
        comment: "Not scam token",
      },
    ]);
  });

  it("fetches WebSocket info", async () => {
    const mockFetchResponse: Response = {
      ok: true,
      json: jest.fn().mockResolvedValue(mockWebSocketInfo),
    } as any as Response;

    mockFetchJwt.mockResolvedValueOnce(mockJwt);
    mockFetch.mockResolvedValueOnce(mockFetchResponse);

    const fetchedValue = await fetchWebSocketInfo();
    expect(fetchedValue).toStrictEqual({
      WEBSOCKET_URL: "ws://localhost:1234",
      WEBSOCKET_API_KEY: "abcxyz",
    });
  });

  it("should fail to fetch the WebSocket info from the database, but returns {}", async () => {
    const mockFetchResponse: Response = {
      ok: false,
      json: jest.fn().mockResolvedValue(mockWebSocketInfo),
    } as any as Response;

    mockFetchJwt.mockResolvedValueOnce(mockJwt);
    mockFetch.mockResolvedValueOnce(mockFetchResponse);

    const fetchedValue = await fetchWebSocketInfo();
    expect(fetchedValue).toStrictEqual({ WEBSOCKET_URL: "", WEBSOCKET_API_KEY: "" });
  });
});
