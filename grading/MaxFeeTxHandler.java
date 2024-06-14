import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;
import java.util.Arrays;

public class MaxFeeTxHandler {

    private UTXOPool utxoPool;
   
    /** Creates a public ledger whose current UTXOPool (collection of unspent
     * transaction outputs) is utxoPool. This should make a defensive copy of
     * utxoPool by using the UTXOPool(UTXOPool uPool) constructor.
     */
    public MaxFeeTxHandler(UTXOPool utxoPool) {
        this.utxoPool = new UTXOPool(utxoPool);
    }

    /**
     * Returns true if:
     * (1) all outputs claimed by tx are in the current UTXO pool, 
     * (2) the signatures on each input of tx are valid, 
     * (3) no UTXO is claimed multiple times by tx,
     * (4) all of tx's output values are non-negative, and
     * (5) the sum of tx's input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        HashSet<UTXO> utxoClaimedSet = new HashSet<UTXO>();  // For (3)
        double sumofInputs = 0.0;   // For (5)
        double sumofOutputs = 0.0;  // For (5)

        // Handles conditions (1), (2), and (3)
        for (int i = 0; i < tx.numInputs(); ++i) {
            Transaction.Input TxInput = tx.getInput(i);

            // Handle condition (1)
            UTXO utxo = new UTXO(TxInput.prevTxHash, TxInput.outputIndex);

            if (this.utxoPool.contains(utxo) == false) {
                return false;
            }

            // Handle condition (2)
            RSAKey publicRSAKey = this.utxoPool.getTxOutput(utxo).address;
            byte[] message = tx.getRawDataToSign(i);
            byte[] signature = TxInput.signature;

            if (publicRSAKey.verifySignature(message, signature) == false) {
                return false;
            }

            // Handle condition (3)
            if (utxoClaimedSet.contains(utxo)) {
                return false;
            }
            utxoClaimedSet.add(utxo);

            // Take sum of inputs for (5)
            sumofInputs += this.utxoPool.getTxOutput(utxo).value;
        }

        // Handle condition (4)
        for (int i = 0; i < tx.numOutputs(); ++i) {
            Transaction.Output TxOutput = tx.getOutput(i);

            if (TxOutput.value < 0.0) {
                return false;
            }

            // Take sum of outputs for (5)
            sumofOutputs += TxOutput.value;
        }

        // Handle condition (5)
        if (sumofInputs < sumofOutputs) {
            return false;
        }

        /** 
         *  If we reached here, all 5 conditions have passed
         *  and we can return true.
         */
        return true;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed
     * transactions, checking each transaction for correctness,
     * returning a mutually valid array of accepted transactions,
     * and updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {

        // Convert possibleTxs to an ArrayList
        ArrayList<Transaction> sortedTxs = new ArrayList<>(Arrays.asList(possibleTxs));

        // Sort using a custom sort (sorting by transaction fees)
        sortedTxs.sort((firstTx, secondTx) -> {

            // Get fee for transaction: firstTx

            double sumofInputs = 0.0;
            double sumofOutputs = 0.0;

            // Get the sum of the inputs for the first transaction
            for (int i = 0; i < firstTx.numInputs(); ++i) {
                Transaction.Input TxInput = firstTx.getInput(i);
                UTXO utxo = new UTXO(TxInput.prevTxHash, TxInput.outputIndex);
                if (this.utxoPool.contains(utxo)) {
                    sumofInputs += this.utxoPool.getTxOutput(utxo).value;
                }
            }

            // Get the sum of the outputs for the first transaction
            for (int i = 0; i < firstTx.numOutputs(); ++i) {
                Transaction.Output TxOutput = firstTx.getOutput(i);
                sumofOutputs += TxOutput.value;
            }

            // Calculate fee for the first transaction
            double feesForFirstTx = sumofInputs - sumofOutputs;

            // Get fee for transaction 2: secondTx

            sumofInputs = 0.0;
            sumofOutputs = 0.0;

            // Get the sum of the inputs for the second transaction
            for (int i = 0; i < secondTx.numInputs(); ++i) {
                Transaction.Input TxInput = secondTx.getInput(i);
                UTXO utxo = new UTXO(TxInput.prevTxHash, TxInput.outputIndex);
                if (this.utxoPool.contains(utxo)) {
                    sumofInputs += this.utxoPool.getTxOutput(utxo).value;
                }
            }

            // Get the sum of the outputs for the second transaction
            for (int i = 0; i < secondTx.numOutputs(); ++i) {
                Transaction.Output TxOutput = secondTx.getOutput(i);
                sumofOutputs += TxOutput.value;
            }

            // Calculate fee for the second transaction
            double feesForSecondTx = sumofInputs - sumofOutputs;

            /** 
                If feesForSecondTx > feesForFirstTx, place feesForSecondTx before feesForFirstTx
                If feesForSecondTx < feesForFirstTx, place feesForSecondTx after feesForFirstTx
             */
            return Double.compare(feesForSecondTx, feesForFirstTx);
        });
        
        // Append the Txs. There's 1 transaction (Transaction@1b0258ab) that fails condition (1) the first iteration.
        sortedTxs.addAll(sortedTxs);

        ArrayList<Transaction> acceptedTxs = new ArrayList<Transaction>();

        for (int i = 0; i < sortedTxs.size(); ++i){
            Transaction Tx = sortedTxs.get(i);
            if (isValidTx(Tx) == true) {
                // Accept transaction since it's valid
                acceptedTxs.add(Tx);

                // Update UTXO pool for inputs
                for (int j = 0; j < Tx.numInputs(); ++j) {
                    Transaction.Input TxInput = Tx.getInput(j);
                    UTXO utxo = new UTXO(TxInput.prevTxHash, TxInput.outputIndex);
                    this.utxoPool.removeUTXO(utxo);
                }
            
                // Update UTXO pool for outputs
                for (int j = 0; j < Tx.numOutputs(); ++j) {
                    Transaction.Output TxOutput = Tx.getOutput(j);
                    UTXO utxo = new UTXO(Tx.getHash(), j);
                    this.utxoPool.addUTXO(utxo, TxOutput);
                }
            }
        }
        /** 
         *  Need to convert acceptTxs from ArrayList to an array.
         *  Also need to get the number of accepted transactions to declare the array.
         */
        int size = acceptedTxs.size();
        return acceptedTxs.toArray(new Transaction[size]);
    }

}
