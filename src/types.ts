export type Exploit = {
  id: number;
  name: string;
  types: string;
};

export type RugPullResult = {
  chain_id: string;
  address: string;
  deployer_addr: string;
  name: string;
  symbol: string;
  created_at: string;
  exploits: Exploit[];
};

export type RugPullPayload = {
  message: string;
  total: number;
  result: RugPullResult[];
};

export type FalsePositiveInfo = {
  contractName: string;
  contractAddress: string;
  deployerAddress: string;
  comment: string;
};

export type FalsePositiveDatabase = {
  [key: string]: FalsePositiveInfo;
};
