import {
    Finding,
    FindingType,
    FindingSeverity,
    Label,
    EntityType
} from "forta-agent";

export function createFinding(entry: any): Finding {
    return Finding.fromObject({
        name: "Rug pull contract detected",
        description: entry["exploits"][0]["name"],
        alertId: "SOLIDUS-RUG-PULL",
        severity: FindingSeverity.Critical,
        type: FindingType.Scam,
        metadata: {
          chainId: entry["chain_id"],
          deployerAddress: entry["deployer_addr"],
          createdAddress: entry["address"],
          creationTime: entry["created_at"],
          tokenName: entry["name"],
          tokenSymbol: entry["symbol"],
          exploitName: entry["exploits"][0]["name"],
          exploitType: entry["exploits"][0]["type"]
        },
        labels: [
          Label.fromObject({
            entity: entry["address"],
            entityType: EntityType.Address,
            label: "Rug pull contract",
            confidence: 0.99,
            remove: false,
            createdAt: entry["created_at"]
          }),
          Label.fromObject({
            entity: entry["deployer_addr"],
            entityType: EntityType.Address,
            label: "Rug pull contract deployer",
            confidence: 0.99,
            remove: false,
          }),
        ]
    });
};