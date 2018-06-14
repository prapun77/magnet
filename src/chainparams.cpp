// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assert.h"

#include "chainparams.h"
#include "main.h"
#include "util.h"
#include "base58.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

//
// Main network
//

// Convert the pnSeeds array into usable address objects.
static void convertSeeds(std::vector<CAddress> &vSeedsOut, const unsigned int *data, unsigned int count, int port)
{
     // It'll only connect to one or two seed nodes because once it connects,
     // it'll get a pile of addresses with newer timestamps.
     // Seed nodes are given a random 'last seen time' of between one and two
     // weeks ago.
     const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int k = 0; k < count; ++k)
    {
        struct in_addr ip;
        unsigned int i = data[k], t;
        
        // -- convert to big endian
        t =   (i & 0x000000ff) << 24u
            | (i & 0x0000ff00) << 8u
            | (i & 0x00ff0000) >> 8u
            | (i & 0xff000000) >> 24u;
        
        memcpy(&ip, &t, sizeof(ip));
        
        CAddress addr(CService(ip, port));
        addr.nTime = GetTime()-GetRand(nOneWeek)-nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

// Hardcoded seeds.
// At last resort we will connect to these hardcoded seeds
// if DNS seeds are not available (magdns1-3.magnetwork.io).
static void getHardcodedSeeds(std::vector<CAddress> &vSeedsOut)
{
    std::vector<std::string> ips;

    const int64_t oneWeek = 7 * 24 * 60 * 60;
    for (size_t i = 0; i < ips.size(); ++i)
    {
        CAddress addr(CService(ips[i], 17711));
        addr.nTime = GetTime() - GetRand(oneWeek) - oneWeek;
        vSeedsOut.push_back(addr);
    }
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 93;
        pchMessageStart[1] = 67;
        pchMessageStart[2] = 139;
        pchMessageStart[3] = 215;
        vAlertPubKey = ParseHex("04c60a03d88d4ddb1cc1f833564d55d15e268a01dd1a79ba02689d5644a770e1206e290b1a2106991f76b990d4b64a9840947a693ff8ca07183f3fdc8e85fd6efb");
        nDefaultPort = 17711;
        nRPCPort = 17712;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);

        // Build the genesis block.
            // transaction:  Coinbase(hash=3c8eb5ab2277426f2f48bd70eeb32416b1c94456a3e56e1871d15b568dde3e1e, nTime=1508673600, ver=1, vin.size=1, vout.size=1, nLockTime=0)
            // CTxIn(COutPoint(0000000000, 4294967295), coinbase 00012a284f63742032322c20323031373a20426974636f696e2070726963652061626f76652024362c303030)
            // CTxOut(empty)

        const char* pszTimestamp = "June 14, 2018:  Thailand's ‘War Elephants’ as the team is known were eliminated in the third round this year and couldn’t qualify for the World Cup";
        std::vector<CTxIn> vin;
        vin.resize(1);
        vin[0].scriptSig = CScript() << 0 << CBigNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        std::vector<CTxOut> vout;
        vout.resize(1);
        vout[0].SetEmpty();
       // vout[0].nValue = 5000000 * COIN;
       // vout[0].scriptPubKey.SetDestination(address.Get());
       // vout[0].scriptPubKey = CScript() << ParseHex("04fe06a25ca1e7a2b91008c9c42aef0fe447509fbb2b133ad2cd421ce7d9a204a1be63b5d4f7dd12ec372b03bfb3d9c1105f45cee37da0a035d875f732743dc038") << OP_CHECKSIG;
        CTransaction txNew(1, 1528959903, vin, vout, 0);

        LogPrintf("genesis mainnet transaction:  %s\n", txNew.ToString().c_str());

        genesis.vtx.push_back(txNew);

        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1528959903 ;
        genesis.nBits    = bnProofOfWorkLimit.GetCompact(); 
        genesis.nNonce   = 37257;

        // Mine the genesis block.
        if (true)
        {
            hashGenesisBlock = uint256("0x01");
            LogPrintf("recalculating params for mainnet.\n");
            LogPrintf("old mainnet genesis nonce: %d\n", genesis.nNonce);
            LogPrintf("old mainnet genesis hash:  %s\n", hashGenesisBlock.ToString().c_str());
            // deliberately empty for loop finds nonce value.
            for(genesis.nNonce = 0; genesis.GetHash() > (~uint256(0) >> 16); genesis.nNonce++){ }
            LogPrintf("new mainnet genesis merkle root: %s\n", genesis.hashMerkleRoot.ToString().c_str());
            LogPrintf("new mainnet genesis nonce: %d\n", genesis.nNonce);
            LogPrintf("new mainnet genesis hash: %s\n", genesis.GetHash().ToString().c_str());
        }

        hashGenesisBlock = genesis.GetHash();

        assert(hashGenesisBlock == uint256("0x0000f95359bf62a4f900903f8fa14827df2cf1d91142ee08fd2b17f1db3d155b"));
        assert(genesis.hashMerkleRoot == uint256("0x8df429a49645fa23294a6da824f88c0c6ebde633b282f4e81b66e98f3be4c93d"));

        
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,23);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,86);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,82);
        base58Prefixes[STEALTH_ADDRESS] = std::vector<unsigned char>(1,44);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x06)(0x18)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x06)(0x18)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        //convertSeeds(vFixedSeeds, pnSeed, ARRAYLEN(pnSeed), nDefaultPort);
//        vFixedSeeds.clear();
//        vSeeds.clear();

        getHardcodedSeeds(vFixedSeeds);

        nPoolMaxTransactions = 3;
        //strSporkKey = "046f78dcf911fbd61910136f7f0f8d90578f68d0b3ac973b5040fb7afb501b5939f39b108b0569dca71488f5bbf498d92e4d1194f6f941307ffd95f75e76869f0e";
        //strMasternodePaymentsPubKey = "046f78dcf911fbd61910136f7f0f8d90578f68d0b3ac973b5040fb7afb501b5939f39b108b0569dca71488f5bbf498d92e4d1194f6f941307ffd95f75e76869f0e";
        strDarksendPoolDummyAddress = "MqXy5e1QhqYgUqXn8mWqhn1dogj2caf7hb";

        // Halving reward every 360000 blocks - 50% PoS.
        nLastPOWBlock = 360000 * 30 * 2 + 1;
        nPOSStartBlock = 1000;
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet
//

class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 213;
        pchMessageStart[1] = 69;
        pchMessageStart[2] = 15;
        pchMessageStart[3] = 121;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);
        vAlertPubKey = ParseHex("04fe06a25ca1e7a2b91008c9c42aef0fe447509fbb2b133ad2cd421ce7d9a204a1be63b5d4f7dd12ec372b03bfb3d9c1105f45cee37da0a035d875f732743dc038");
        nDefaultPort = 27178;
        nRPCPort = 27179;
        strDataDir = "testnet";

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x0000f95359bf62a4f900903f8fa14827df2cf1d91142ee08fd2b17f1db3d155b"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,77);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,194);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,84);
        base58Prefixes[STEALTH_ADDRESS] = std::vector<unsigned char>(1,41);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x05)(0x39)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x05)(0x39)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        convertSeeds(vFixedSeeds, pnTestnetSeed, ARRAYLEN(pnTestnetSeed), nDefaultPort);

        nLastPOWBlock = 0x7fffffff;
    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    
    bool fTestNet = GetBoolArg("-testnet", false);
    
    if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}
