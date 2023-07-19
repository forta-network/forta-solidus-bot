import { createAddress } from "forta-agent-tools";

const mockDataResults: any[] = [
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
];
  
export const mockDataOneResult: any = {
    "message": "OK",
    "total": 1,
    "result": [
        mockDataResults[0]
    ]
}
  
export const mockDataTwoResults: any = {
    "message": "OK",
    "total": 2,
    "result": [
        mockDataResults[1],
        mockDataResults[2],
    ]
}
  
export const mockDataThreeResults: any = {
    "message": "OK",
    "total": 3,
    "result": mockDataResults
}