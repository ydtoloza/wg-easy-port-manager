'use strict';

module.exports = class ServerError extends Error {

  constructor(message, statusCode = 500, rollbackErrors = []) {
    super(message);
    this.statusCode = statusCode;
    this.rollbackErrors = rollbackErrors;
  }

};
