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
const KEY_LENGTH = 33; // 33 bytes = 264 bits == 24 word passphrase
const PBKDF2_DIGEST = 'sha512'; // Should be 'hmac-sha512'

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

        // calculate passphrase
        this.passPhrase = this.words();

        //show client passphrase
        this.printPassphrase();
        console.log(this.passphraseArr);
    }


    get derivedSeed(){
        return this.seq;
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

    //chooses 3 random words for the client to verify
    //returns the status of the verification
    verifyPassphrase(){
        let verified = true;
        let firstInput = "";
        let secondInput = "";
        let thirdInput = "";

        let firstIndex = 0;
        let secondIndex =0;
        let thirdIndex = 0;

        console.log("" + this.password + " must verify passphrase.");


        //pick 3 random numbers 0-24
        //firstIndex, secondIndex, thirdIndex
        //check that indexes don't equal each other

        while(firstIndex === secondIndex || secondIndex === thirdIndex || firstIndex === thirdIndex) {
            firstIndex = Math.ceil(Math.random() * 24);
            secondIndex = Math.ceil(Math.random() * 24);
            thirdIndex = Math.ceil(Math.random() * 24);
        }

        //show user passphrase list with 3 numbers empty
        let phrase = "";
        let phraseArr = this.passPhrase.split(" ");
        for(let i = 1; i < phraseArr.length; i++) {
            if (i === firstIndex || i === secondIndex || i === thirdIndex) {
                phrase = phrase + "" + i + ".      ";
            }
            else {
            phrase = phrase + "" + i + ". " + phraseArr[i - 1] + " ";
            }

            if(i % 4 == 0){
                phrase = phrase + "\n";
            }
        }
        console.log(phrase);

        //take UI
        console.log("Enter word for number " + firstIndex + ". ");
        //take UI
        //firstInput = this.passphraseArr[firstIndex];

        console.log("Enter word for number " + secondIndex + ". ");
        //take UI
        //secondInput = this.passphraseArr[secondIndex];


        console.log("Enter word for number " + thirdIndex + ". ");
        //take UI
        //thirdInput = this.passphraseArr[thirdIndex];


        //verify UI equals passphrase
        if(firstInput !== this.passphraseArr[firstIndex]){
            verified = false;
        }
        if(secondInput !== this.passphraseArr[secondIndex]){
            verified = false;
        }
        if(thirdInput !== this.passphraseArr[thirdIndex]){
            verified = false;
        }
        console.log(verified);
        return verified;
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
