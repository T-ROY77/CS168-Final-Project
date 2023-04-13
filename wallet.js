"use strict";

// let Blockchain = require('./blockchain.js');
//
// let utils = require('./utils.js');

let crypto = require('crypto');


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
        crypto.pbkdf2(this.password, Date.now().toString(), 100000, 16,
            'sha512', (err, derivedKey) => {

                if (err) throw err;

                // Prints derivedKey
                this.key = derivedKey;
                console.log(this.key.toString('hex'));
            });
    }
};
