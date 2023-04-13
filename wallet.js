"use strict";

// let Blockchain = require('./blockchain.js');
//
// let utils = require('./utils.js');

let crypto = require('crypto');
const fs = require('fs');


const WORD_LIST_FILE = './english.json';
const HASH_ALG = 'sha256';
const NUM_BYTES = 33;

const SALT_BASE = "mnemonic";
const NUM_PBKDF2_ROUNDS = 2048;
const KEY_LENGTH = 33; // 33 bytes = 264 bits
const PBKDF2_DIGEST = 'sha512'; // Should be 'hmac-sha512'

/**
 *
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

    // Takes a buffer and returns an array of 11-bit unsigned ints
    static split(seq) {
        // convert seq to binary string
        let bitString = '';
        for (let byte of seq.values()) {
            let bs = this.convertByteToBinString(byte);
            bitString += bs;
        }

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
     * The net object determines how the client communicates
     * with other entities in the system. (This approach allows us to
     * simplify our testing setup.)
     *
     * @constructor
     * @param {Object} obj - The properties of the client.
     * @param {String} [obj.password] - The client's password.
     */
    constructor({password} = {}) {
        let content = fs.readFileSync(WORD_LIST_FILE);
        this.wordlist = JSON.parse(content);

        this.password = password;

        // Creating the sequence
        this.seq = Buffer.alloc(NUM_BYTES);
        crypto.randomFillSync(this.seq, 0, NUM_BYTES);

//generate random 512 bit seed
// based on timestamp?
//generate 12 indices based on random seed(0-2047)
//get 12 english words from array and 12 indices
//each word is 11 bits
//show client passphrase
//this.wallet = new wallet();
        let key = crypto.pbkdf2Sync(this.password, SALT_BASE + Date.now().toString(), NUM_PBKDF2_ROUNDS, KEY_LENGTH, PBKDF2_DIGEST);
        this.seed = key.toString('hex');

        this.passPhrase = this.words();

        console.log("passphrase for " + this.password);
        console.log(this.passPhrase);

    }


    get derivedSeed(){
        return this.seed;
    }

    calculateSequence(words) {
        let wordArray = words.split(' ');
        // Extra byte for checksum
        this.seq = Buffer.alloc(NUM_BYTES + 1);

        //
        // ***YOUR CODE HERE***
        //
        // Determine the string of bits from the specified words.
        // Remember that each word translates to an 11-bit number,
        // so conversion can be a little awkward.
        //
        // Using that string of bits, convert to bytes and write
        // to the `this.seq` buffer.

        let bits = "";

        for(let i = 0; i < wordArray.length; i++){
            bits = this.constructor.translate11bit(wordArray[i]);
        }

        this.seq.writeIntBE(this.constructor.convertBinStringToByte(bits));



        //console.log(bits);
        console.log(this.seq);

    }

    // Returns a string with the sequence of words matching to
    // the random sequence.
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
