var passport = module.parent.require('passport'),
    passportLocal = module.parent.require('passport-local').Strategy,
    plugin = {};
var async = require('async');
var request = require('request');

plugin.thirdLogin = function() {
    passport.use(new passportLocal({passReqToCallback: true}, plugin.continueLogin));
};

plugin.continueLogin = function(req, username, password, next) {
    var user = module.parent.require('./user');
    var userObj = {}
    async.waterfall([
        function (callback) {
            if (!username || !password) {
                return callback(new Error('Il nome utente o la password non possono essere vuoti'));
            } else {
                request.post({url:'https://www.simosnap.org/rest/service.php/rlogin', form:{username: username, password: password}}, function(error, response, body) {
                    if (!error && response.statusCode == 200) {
                        const data = JSON.parse(body)
                        //console.log(data);
                        if (data.ERROR == null) {
                            if (data.UNCONFIRMED == null) {
                                userObj = data
                                return callback(null, userObj);
                            } else {
                                //console.log(data.msg)
                                return callback(new Error("Account non confermato."));
                            }
                        } else {
                            //console.log(data.msg)
                            return callback(new Error("Accesso non riuscito."));
                        }
                    } else {
                        return callback(new Error('Errore di rete...'));
                    }
                    if (error) {
                        return callback(new Error('Errore'));
                    }
                })
            }
        },
        function (userObj, callback) {
            user.getUidByEmail(String(userObj.email), callback)
        },
        function (_uid, callback) {
            if (!_uid) {
                user.create({
                    username: userObj.display,
                    email: userObj.email
                }, callback);
            } else {
                callback(null, _uid)
            }
        },  function (_uid, callback) {
            if (_uid) {
                next(null, {
                    uid: _uid
                }, '[[success:authentication-successful]]');
            } else {
                return callback(new Error('L\'utente non esiste'));
            }
        }], function(error, res) {
            if (error) {
                next(error);
            }
        })
};

module.exports = plugin;
