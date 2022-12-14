package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	//"github.com/ethereum/go-ethereum/crypto/blake2b"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/crypto/sha3"
)

func main() {
	endpoint := "https://testchain.metamemo.one:24180"
	fmt.Println("dialing endpoint:", endpoint)
	client, err := ethclient.Dial(endpoint)
	if err != nil {
		log.Fatal(err)
	}

	// sender sk
	privateKey, err := crypto.HexToECDSA("0a95533a110ee10bdaa902fed92e56f3f7709a532e22b5974c03c0251648a5d4")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("sender sk:", privateKey)

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	// get sender address
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	fmt.Println("sender address:", fromAddress)

	// get sender nonce
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatal(err)
	}

	// value to send
	value := big.NewInt(0) // in wei (0 eth)

	// get gas price
	fmt.Println("getting gasPrice..")
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("gasPrice:", gasPrice)

	// receiver
	toAddress := common.HexToAddress("0x24E1B31Faa53b9E9d19107C595af12978abAc030")
	fmt.Println("to address:", toAddress)
	// erc20 address
	tokenAddress := common.HexToAddress("0xf3783070Ffe8eDd3C7F89bc136ba7c0512F18627")
	fmt.Println("erc20 token addr:", tokenAddress)

	// method signature
	fmt.Println("getting methodID from fnSig..")
	transferFnSignature := []byte("transfer(address,uint256)")
	hash := sha3.NewLegacyKeccak256()
	hash.Write(transferFnSignature)
	methodID := hash.Sum(nil)[:4]
	fmt.Println(hexutil.Encode(methodID)) // 0xa9059cbb

	// pad address to 32 bytes
	fmt.Println("padding address..")
	paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
	fmt.Println(hexutil.Encode(paddedAddress)) // 0x0000000000000000000000004592d8f8d7b001e72cb26a73e4fa1806a51ac79d

	// amount to be sent
	fmt.Println("padding amount..")
	amount := new(big.Int)
	amount.SetString("1000000000000000000", 10) // 1 token
	// pad amount to 32 bytes
	paddedAmount := common.LeftPadBytes(amount.Bytes(), 32)
	fmt.Println(hexutil.Encode(paddedAmount)) // 0x00000000000000000000000000000000000000000000003635c9adc5dea00000

	// construct trasaction data
	fmt.Println("constructing tx data..")
	var data []byte
	data = append(data, methodID...)
	data = append(data, paddedAddress...)
	data = append(data, paddedAmount...)
	fmt.Printf("tx data: %x\n", data)

	gasLimit := uint64(300000)

	// construct tx with all parts
	fmt.Println("constructing tx..")
	tx := types.NewTransaction(nonce, tokenAddress, value, gasLimit, gasPrice, data)

	// get chainID
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("chainID:", chainID)

	// sign tx
	fmt.Println("signing tx..")
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	// send tx
	fmt.Println("sending tx..")
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("tx sent: %s\n", signedTx.Hash().Hex()) // tx sent: 0xa56316b637a94c4cc0331c73ef26389d6c097506d581073f927275e7a6ece0bc

	WaitTx(endpoint, signedTx.Hash())
}

//GetTransactionReceipt ????????????hash??????????????????
func getTransactionReceipt(endPoint string, hash common.Hash) *types.Receipt {
	client, err := ethclient.Dial(endPoint)
	if err != nil {
		return nil
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	receipt, err := client.TransactionReceipt(ctx, hash)
	if err != nil {
		fmt.Printf("get transaction %s receipt fail: %s", hash, err)
	}
	return receipt
}

func WaitTx(ep string, txHash common.Hash) {
	fmt.Println("tx hash:", txHash)

	fmt.Println("waiting tx complete...")

	time.Sleep(30 * time.Second)
	receipt := getTransactionReceipt(ep, txHash)
	fmt.Println("tx status:", receipt.Status)
}
