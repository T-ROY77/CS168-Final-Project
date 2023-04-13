"use strict";

// let Blockchain = require('./blockchain.js');
//
// let utils = require('./utils.js');

let crypto = require('crypto');

const WORD_LIST_FILE = './english.json';
const HASH_ALG = 'sha256';
const NUM_BYTES = 32;

const SALT_BASE = "mnemonic";
const NUM_PBKDF2_ROUNDS = 2048;
const KEY_LENGTH = 33; // 33 bytes = 264 bits
const PBKDF2_DIGEST = 'sha512'; // Should be 'hmac-sha512'

/**
 *
 */
module.exports = class wallet {

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

        this.password = password;
//generate random 512 bit seed
// based on timestamp?
//generate 12 indices based on random seed(0-2047)
//get 12 english words from array and 12 indices
//each word is 11 bits
//show client passphrase
//this.wallet = new wallet();
        let key = crypto.pbkdf2Sync(this.password, SALT_BASE + Date.now().toString(), NUM_PBKDF2_ROUNDS, KEY_LENGTH, PBKDF2_DIGEST);
        console.log(key.toString('hex'));
        this.key = key.toString('hex');


    }


    get derivedKey(){
        return this.key;
    }
};
