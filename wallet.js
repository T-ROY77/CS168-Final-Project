"use strict";

let crypto = require('crypto');
const fs = require('fs');
const utils = require("./utils");


const WORD_LIST_FILE = './english.json';
const SALT_BASE = "mnemonic";
const NUM_PBKDF2_ROUNDS = 2048;
const KEY_LENGTH = 33; // 33 bytes = 264 bits == 24 word passphrase + 8-bit checksum
const PBKDF2_DIGEST = 'sha512';

/**
 * A wallet has a seed which is generated from pbkdf2,
 * a passphrase generated from the seed, and a binary key generated from the passphrase
 *
 * Every client has a wallet
 */
module.exports = class wallet {


    /**
     * Converts a byte to a string of zeroes and ones.
     *
     * This method is used to convert a byte from the randomly generated seed into binary.
     *
     * @param {String} byte the byte to translate
     *
     * @return {String} the binary string
     */
    static convertByteToBinString(byte) {
        let bs = "";
        // Test each bit individually, adding either a 1 or a 0.
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

    /**
     * Converts a buffer of bytes to a string in binary
     *
     * This method is used to convert the randomly generated seed into the binary key.
     *
     * @param {String} byte the buffer to translate
     *
     * @return {String} the binary key
     */
    static convertSeqtoBin(seq){
        // convert seq to binary string
        let bitString = '';
        for (let byte of seq.values()) {
            let bs = this.convertByteToBinString(byte);
            bitString += bs;
        }
        return bitString;
    }


    /**
     * Converts a buffer of bytes into an array of 11-bit unsigned ints
     *
     * This method is used to convert the randomly generated seed into the passphrase.
     *
     * @param {String} seq the buffer to translate
     *
     * @return {int[]} the array of ints
     */
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
     * The password is used in the pbkdf function to calculate the random seed.
     * The passphrase and binary key are calculated from the random seed.
     *
     *
     * @constructor
     * @param {String} [obj.password] - The client's password. (set to client's name)
     */
    constructor({password} = {}) {

        //set the wordlist
        let content = fs.readFileSync(WORD_LIST_FILE);
        this.wordlist = JSON.parse(content);

        //password for creating seed
        this.password = password;

        //create the random seed
        this.seed = crypto.pbkdf2Sync(this.password, SALT_BASE + Date.now().toString(), NUM_PBKDF2_ROUNDS, KEY_LENGTH, PBKDF2_DIGEST);

        //calculate binary key from seed
        this.binKey = this.constructor.convertSeqtoBin(this.seed);

        //calculate passphrase
        this.passPhrase = this.words();

        //keypair chain
        this.keyPairChain = [];
        this.keyPairChain.push(utils.generateKeypair());

        //show client passphrase
        this.printPassphrase();
    }

    /**
     * Prints the passphrase stored in this.passphrase
     *
     * This method is used to show the client their passphrase that was calculated from the
     * randomly generated seed
     */
    printPassphrase(){
        console.log("Passphrase for " + this.password);

        let phrase = "";

        //split the passphrase string into an array of words
        let phraseArr = this.passPhrase.split(" ");

        //print the index numbers along with the words
        for(let i = 1; i < phraseArr.length; i++){
            phrase = phrase + "" + i + ". " + phraseArr[i-1] + "  ";
            if(i % 4 == 0){
                phrase = phrase + "\n";
            }
        }
        this.passphraseArr = phraseArr;
        console.log(phrase);
    }

    /**
     * Takes the randomly generated seed as an array of 11-bit numbers
     * Converts each number into a word from the english.JSON file
     *
     * This method is used to calculate the 24 word passphrase from the randomly generated seed.
     * This method is part of BIP-39
     *
     * @return {String} the 24 word passphrase as a space-delimited string
     */
    words() {
        // gets the seed as an array of 11-bit numbers.
        let arr = this.constructor.split(this.seed);

        // Convert 11-bit numbers to the corresponding words from the dictionary,
        // join together into a space-delimited string, and return the string.
        let passphrase = "";
        for(let i = 0; i < arr.length; i++){
            passphrase += this.wordlist[arr[i]] + " ";
        }

        return passphrase;
    }
};
