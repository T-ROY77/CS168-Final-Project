"use strict";

// let Blockchain = require('./blockchain.js');
//
// let utils = require('./utils.js');

let crypto = require('crypto');
const fs = require('fs');
const readline = require('readline');
const utils = require("./utils");


const rl =
    readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });


const WORD_LIST_FILE = './english.json';
const HASH_ALG = 'sha256';
const NUM_BYTES = 33;

const SALT_BASE = "mnemonic";
const NUM_PBKDF2_ROUNDS = 2048;
const KEY_LENGTH = 33; // 33 bytes = 264 bits == 24 word passphrase + 8-bit checksum
const PBKDF2_DIGEST = 'sha512';

/**
 * A wallet has a passphrase and a seed which is generated from pbkdf2
 * It can calculate the passphrase from the word list and show the client their personal passphrase
 */
module.exports = class wallet {


    // Converts a byte to a string of zeroes and ones.
    static convertByteToBinString(byte) {
        let bs = "";
        // Test each bit individually, appending either a 1 or a 0.
        bs += byte & 0x80 ? "1" : "0";
        bs += byte & 0x40 ? "1" : "0";
        bs += byte & 0x20 ? "1" : "0";
        bs += byte & 0x10 ? "1" : "0";
        bs += byte & 0x08 ? "1" : "0";
        bs += byte & 0x04 ? "1" : "0";
        bs += byte & 0x02 ? "1" : "0";
        bs += byte & 0x01 ? "1" : "0";
        return bs;
    }

    // Converts a string of zeroes and ones to a byte
    static convertBinStringToByte(bs) {
        return parseInt(bs, 2);
    }

    // Converts an 11-bit number to a string of 0's and 1's.
    static translate11bit(n) {
        let bitPosVal = 1024;
        let bs = "";
        while (bitPosVal >= 1) {
            if (n >= bitPosVal) {
                bs += "1";
                n -= bitPosVal;
            } else {
                bs += "0";
            }
            bitPosVal = bitPosVal / 2;
        }
        return bs;
    }

    // Takes a buffer and returns a string in binary
    static convertSeqtoBin(seq){
        // convert seq to binary string
        let bitString = '';
        for (let byte of seq.values()) {
            let bs = this.convertByteToBinString(byte);
            bitString += bs;
        }
        return bitString;
    }


    // Takes a buffer and returns an array of 11-bit unsigned ints
    static split(seq) {
        // convert seq to binary string
        let bitString = this.convertSeqtoBin(seq);

        // break up binary into 11bits
        let elevenBits = bitString.match(/.{11}/g);

        // convert 11bits to ints
        return elevenBits.map(bs => {
            let bitPosVal = 1024;
            let val = 0;
            for (let i=0; i<bs.length; i++) {
                let bit = bs.charAt(i);
                if (bit === "1") val += bitPosVal;
                bitPosVal = bitPosVal / 2;
            }
            return val;
        });
    }


    /**
     * The password is used in the pbkdf function to calculate the random seed
     *
     * @constructor
     * @param {Object} obj - The properties of the client.
     * @param {String} [obj.password] - The client's password.
     */
    constructor({password} = {}) {

        //setting the wordlist
        let content = fs.readFileSync(WORD_LIST_FILE);
        this.wordlist = JSON.parse(content);

        this.password = password;

        // Creating the random sequence
        this.seq = crypto.pbkdf2Sync(this.password, SALT_BASE + Date.now().toString(), NUM_PBKDF2_ROUNDS, KEY_LENGTH, PBKDF2_DIGEST);

        this.binKey = this.constructor.convertSeqtoBin(this.seq);

        // calculate passphrase
        this.passPhrase = this.words();

        //keypair chain
        this.keyPairChain = [];
        this.keyPairChain.push(utils.generateKeypair());

        //console.log(this.keyPairChain);

        //show client passphrase
        this.printPassphrase();
        //console.log(this.binKey);

        //verify wallet
        //this.verifyPassphrase();
    }


    get binaryKey(){
        return this.binKey;
    }

    //prints the passphrase stored in this.passphrase
    printPassphrase(){
        console.log("Passphrase for " + this.password);

        let phrase = "";

        let phraseArr = this.passPhrase.split(" ");
        for(let i = 1; i < phraseArr.length; i++){
            phrase = phrase + "" + i + ". " + phraseArr[i-1] + "  ";
            if(i % 4 == 0){
                phrase = phrase + "\n";
            }
        }
        this.passphraseArr = phraseArr;
        console.log(phrase);
    }

    // Returns a string with the sequence of words matching to the random sequence.
    words() {
        // Returns an array of 11-bit numbers.
        let arr = this.constructor.split(this.seq);

        // Convert 11-bit numbers to the corresponding words from the dictionary,
        // join together into a space-delimited string, and return the string.
        let passphrase = "";
        for(let i = 0; i < arr.length; i++){
            passphrase += this.wordlist[arr[i]] + " ";
        }

        return passphrase;
    }
};
