export type Exploit = {
  id: number;
  name: string;
  types: string;
};

export type ScamTokenResult = {
  chain_id: string;
  address: string;
  deployer_addr: string;
  name: string;
  symbol: string;
  created_at: string;
  exploits: Exploit[];
};

export type FalsePositiveEntry = {
  contractName: string;
  contractAddress: string;
  deployerAddress: string;
  creationTransaction: string,
  chainId: string;
  comment: string;
};

export type WebSocketInfo = {
  WEBSOCKET_URL: string;
  WEBSOCKET_API_KEY: string;
};
