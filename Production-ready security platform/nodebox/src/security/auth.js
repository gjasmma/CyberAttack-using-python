const bcrypt = require("bcrypt");
const { bcryptRounds } = require("../config");

const users = {
  admin: {
    passwordHash: bcrypt.hashSync("Password123!", bcryptRounds),
    role: "superuser",
  },
  guest: {
    passwordHash: bcrypt.hashSync("1234", bcryptRounds),
    role: "viewer",
  },
};

module.exports = { users };
