/**
* This file has been generated by Babel.
* 
* DO NOT EDIT IT DIRECTLY
* 
* Edit the JS source file src/js/push.js
**/
"use strict";

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

/*!
 * Module dependencies.
 */
var exec = cordova.require('cordova/exec');
var channel = require('cordova/channel');

var PushNotification = /*#__PURE__*/function () {
  /**
   * PushNotification constructor.
   *
   * @param {Object} options to initiate Push Notifications.
   * @return {PushNotification} instance that can be monitored and cancelled.
   */
  function PushNotification(options) {
    var _this = this;

    _classCallCheck(this, PushNotification);

    this.handlers = {
      registration: [],
      notification: [],
      error: []
    }; // require options parameter

    if (typeof options === 'undefined') {
      throw new Error('The options argument is required.');
    } // store the options to this object instance


    this.options = options; // triggered on registration and notification

    var success = function success(result) {
      if (result && typeof result.registrationId !== 'undefined') {
        _this.emit('registration', result);
      } else if (result && result.additionalData && typeof result.additionalData.actionCallback !== 'undefined') {
        _this.emit(result.additionalData.actionCallback, result);
      } else if (result) {
        _this.emit('notification', result);
      }
    }; // triggered on error


    var fail = function fail(msg) {
      var e = typeof msg === 'string' ? new Error(msg) : msg;

      _this.emit('error', e);
    }; // wait at least one process tick to allow event subscriptions


    setTimeout(function () {
      exec(success, fail, 'PushNotification', 'init', [options]);
    }, 10);
  }

  /**
   * Unregister from push notifications
   */
  _createClass(PushNotification, [{
    key: "unregister",
    value: function unregister(successCallback) {
      var _this2 = this;

      var errorCallback = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : function () {};
      var options = arguments.length > 2 ? arguments[2] : undefined;

      if (typeof errorCallback !== 'function') {
        console.log('PushNotification.unregister failure: failure parameter not a function');
        return;
      }

      if (typeof successCallback !== 'function') {
        console.log('PushNotification.unregister failure: success callback parameter must be a function');
        return;
      }

      var cleanHandlersAndPassThrough = function cleanHandlersAndPassThrough() {
        if (!options) {
          _this2.handlers = {
            registration: [],
            notification: [],
            error: []
          };
        }

        successCallback();
      };

      exec(cleanHandlersAndPassThrough, errorCallback, 'PushNotification', 'unregister', [options]);
    }
    /**
     * subscribe to a topic
     * @param   {String}      topic               topic to subscribe
     * @param   {Function}    successCallback     success callback
     * @param   {Function}    errorCallback       error callback
     * @return  {void}
     */

  }, {
    key: "subscribe",
    value: function subscribe(topic, successCallback) {
      var errorCallback = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : function () {};

      if (typeof errorCallback !== 'function') {
        console.log('PushNotification.subscribe failure: failure parameter not a function');
        return;
      }

      if (typeof successCallback !== 'function') {
        console.log('PushNotification.subscribe failure: success callback parameter must be a function');
        return;
      }

      exec(successCallback, errorCallback, 'PushNotification', 'subscribe', [topic]);
    }
    /**
     * unsubscribe to a topic
     * @param   {String}      topic               topic to unsubscribe
     * @param   {Function}    successCallback     success callback
     * @param   {Function}    errorCallback       error callback
     * @return  {void}
     */

  }, {
    key: "unsubscribe",
    value: function unsubscribe(topic, successCallback) {
      var errorCallback = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : function () {};

      if (typeof errorCallback !== 'function') {
        console.log('PushNotification.unsubscribe failure: failure parameter not a function');
        return;
      }

      if (typeof successCallback !== 'function') {
        console.log('PushNotification.unsubscribe failure: success callback parameter must be a function');
        return;
      }

      exec(successCallback, errorCallback, 'PushNotification', 'unsubscribe', [topic]);
    }
    /**
     * Call this to set the application icon badge
     */

  }, {
    key: "setApplicationIconBadgeNumber",
    value: function setApplicationIconBadgeNumber(successCallback) {
      var errorCallback = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : function () {};
      var badge = arguments.length > 2 ? arguments[2] : undefined;

      if (typeof errorCallback !== 'function') {
        console.log('PushNotification.setApplicationIconBadgeNumber failure: failure ' + 'parameter not a function');
        return;
      }

      if (typeof successCallback !== 'function') {
        console.log('PushNotification.setApplicationIconBadgeNumber failure: success ' + 'callback parameter must be a function');
        return;
      }

      exec(successCallback, errorCallback, 'PushNotification', 'setApplicationIconBadgeNumber', [{
        badge: badge
      }]);
    }
    /**
     * Get the application icon badge
     */

  }, {
    key: "getApplicationIconBadgeNumber",
    value: function getApplicationIconBadgeNumber(successCallback) {
      var errorCallback = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : function () {};

      if (typeof errorCallback !== 'function') {
        console.log('PushNotification.getApplicationIconBadgeNumber failure: failure ' + 'parameter not a function');
        return;
      }

      if (typeof successCallback !== 'function') {
        console.log('PushNotification.getApplicationIconBadgeNumber failure: success ' + 'callback parameter must be a function');
        return;
      }

      exec(successCallback, errorCallback, 'PushNotification', 'getApplicationIconBadgeNumber', []);
    }
    /**
     * Clear all notifications
     */

  }, {
    key: "clearAllNotifications",
    value: function clearAllNotifications() {
      var successCallback = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : function () {};
      var errorCallback = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : function () {};

      if (typeof errorCallback !== 'function') {
        console.log('PushNotification.clearAllNotifications failure: failure parameter not a function');
        return;
      }

      if (typeof successCallback !== 'function') {
        console.log('PushNotification.clearAllNotifications failure: success callback ' + 'parameter must be a function');
        return;
      }

      exec(successCallback, errorCallback, 'PushNotification', 'clearAllNotifications', []);
    }
    /**
     * Clears notifications that have the ID specified.
     * @param  {Function} [successCallback] Callback function to be called on success.
     * @param  {Function} [errorCallback] Callback function to be called when an error is encountered.
     * @param  {Number} id    ID of the notification to be removed.
     */

  }, {
    key: "clearNotification",
    value: function clearNotification() {
      var successCallback = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : function () {};
      var errorCallback = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : function () {};
      var id = arguments.length > 2 ? arguments[2] : undefined;
      var idNumber = parseInt(id, 10);

      if (Number.isNaN(idNumber) || idNumber > Number.MAX_SAFE_INTEGER || idNumber < 0) {
        console.log('PushNotification.clearNotification failure: id parameter must' + 'be a valid integer.');
        return;
      }

      exec(successCallback, errorCallback, 'PushNotification', 'clearNotification', [idNumber]);
    }
    /**
     * Listen for an event.
     *
     * The following events are supported:
     *
     *   - registration
     *   - notification
     *   - error
     *
     * @param {String} eventName to subscribe to.
     * @param {Function} callback triggered on the event.
     */

  }, {
    key: "on",
    value: function on(eventName, callback) {
      if (!Object.prototype.hasOwnProperty.call(this.handlers, eventName)) {
        this.handlers[eventName] = [];
      }

      this.handlers[eventName].push(callback);
    }
    /**
     * Remove event listener.
     *
     * @param {String} eventName to match subscription.
     * @param {Function} handle function associated with event.
     */

  }, {
    key: "off",
    value: function off(eventName, handle) {
      if (Object.prototype.hasOwnProperty.call(this.handlers, eventName)) {
        var handleIndex = this.handlers[eventName].indexOf(handle);

        if (handleIndex >= 0) {
          this.handlers[eventName].splice(handleIndex, 1);
        }
      }
    }
    /**
     * Emit an event.
     *
     * This is intended for internal use only.
     *
     * @param {String} eventName is the event to trigger.
     * @param {*} all arguments are passed to the event listeners.
     *
     * @return {Boolean} is true when the event is triggered otherwise false.
     */

  }, {
    key: "emit",
    value: function emit() {
      for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
        args[_key] = arguments[_key];
      }

      var eventName = args.shift();

      if (!Object.prototype.hasOwnProperty.call(this.handlers, eventName)) {
        return false;
      }

      for (var i = 0, length = this.handlers[eventName].length; i < length; i += 1) {
        var callback = this.handlers[eventName][i];

        if (typeof callback === 'function') {
          callback.apply(void 0, args); // eslint-disable-line node/no-callback-literal
        } else {
          console.log("event handler: ".concat(eventName, " must be a function"));
        }
      }

      return true;
    }
  }, {
    key: "finish",
    value: function finish() {
      var successCallback = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : function () {};
      var errorCallback = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : function () {};
      var id = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 'handler';

      if (typeof successCallback !== 'function') {
        console.log('finish failure: success callback parameter must be a function');
        return;
      }

      if (typeof errorCallback !== 'function') {
        console.log('finish failure: failure parameter not a function');
        return;
      }

      exec(successCallback, errorCallback, 'PushNotification', 'finish', [id]);
    }
  }
  // {
  //   key: "addEventListener",
  //   value: function addEventListener(eventname, globalFlagOrListener, listener){
  //     var _this = this;
  //     var isGlobal = false;
  //     var f = function () { };
  //     if (typeof globalFlagOrListener === 'boolean') {
  //         isGlobal = globalFlagOrListener;
  //         if (!listener)
  //             throw "listener must be defined!";
  //         f = listener;
  //     }
  //     else if (typeof globalFlagOrListener === 'function') {
  //         f = globalFlagOrListener;
  //     }
  //     if (!this._channelExists(eventname)) {
  //         this._channelCreate(eventname);
  //         exec(function () { return _this._channelSubscribe(eventname, f); }, function (err) { return console.log("ERROR addEventListener: ", err); }, "PushNotification", "addEventListener", [eventname, isGlobal]);
  //     }
  //     else {
  //         this._channelSubscribe(eventname, f);
  //     }
  //     exec(successCallback, errorCallback, 'PushNotification', 'addEventListener', [eventname, isGlobal]);
  //   }
  // }
]);

  return PushNotification;
}();
/*!
 * Push Notification Plugin.
 */
//Broadcaster
this._debug = false;
this._channels = {};
this._channelCreate = function (c) {
    if (_this._debug)
        console.log("CHANNEL " + c + " CREATED! ");
    _this._channels[c] = channel.create(c);
};
this._channelDelete = function (c) {
    delete _this._channels[c];
    if (_this._debug)
        console.log("CHANNEL " + c + " DELETED! ");
};
this._channelSubscribe = function (c, f) {
    var channel = _this._channels[c];
    channel.subscribe(f);
    if (_this._debug)
        console.log("CHANNEL " + c + " SUBSCRIBED! " + channel.numHandlers);
    return channel.numHandlers;
};
this._channelUnsubscribe = function (c, f) {
    var channel = _this._channels[c];
    channel.unsubscribe(f);
    if (_this._debug)
        console.log("CHANNEL " + c + " UNSUBSCRIBED! " + channel.numHandlers);
    return channel.numHandlers;
};
this._channelFire = function (event) {
    if (_this._debug)
        console.log("CHANNEL " + event.type + " FIRED! ");
    _this._channels[event.type].fire(event);
};
this._channelExists = function (c) {
    return _this._channels.hasOwnProperty(c);
};

module.exports = {
  /**
   * Register for Push Notifications.
   *
   * This method will instantiate a new copy of the PushNotification object
   * and start the registration process.
   *
   * @param {Object} options
   * @return {PushNotification} instance
   */
  init: function init(options) {
    return new PushNotification(options);
  },
  hasPermission: function hasPermission(successCallback, errorCallback) {
    exec(successCallback, errorCallback, 'PushNotification', 'hasPermission', []);
  },
  createChannel: function createChannel(successCallback, errorCallback, channel) {
    exec(successCallback, errorCallback, 'PushNotification', 'createChannel', [channel]);
  },
  deleteChannel: function deleteChannel(successCallback, errorCallback, channelId) {
    exec(successCallback, errorCallback, 'PushNotification', 'deleteChannel', [channelId]);
  },
  listChannels: function listChannels(successCallback, errorCallback) {
    exec(successCallback, errorCallback, 'PushNotification', 'listChannels', []);
  },
  addEventListener: function addEventListener(successCallback, errorCallback,eventname, globalFlagOrListener, listener) {
      var _this = this;
      var isGlobal = false;
      var f = function () { };
      if (typeof globalFlagOrListener === 'boolean') {
          isGlobal = globalFlagOrListener;
          if (!listener)
              throw "listener must be defined!";
          f = listener;
      }
      else if (typeof globalFlagOrListener === 'function') {
          f = globalFlagOrListener;
      }
      if (!this._channelExists(eventname)) {
          this._channelCreate(eventname);
          exec(function () { return _this._channelSubscribe(eventname, f); }, function (err) { return console.log("ERROR addEventListener: ", err); }, "PushNotification", "addEventListener", [eventname, isGlobal]);
      }
      else {
          this._channelSubscribe(eventname, f);
      }
      // exec(successCallback, errorCallback, 'PushNotification', 'addEventListener', [eventname, isGlobal]);
  },


  /**
   * PushNotification Object.
   *
   * Expose the PushNotification object for direct use
   * and testing. Typically, you should use the
   * .init helper method.
   */
  PushNotification: PushNotification
};

/*!
 * Cordova Broadcaster Plugin.
 */
// var Broadcaster = /** @class */ (function () {
//   function Broadcaster() {
//       var _this = this;
//       this._debug = false;
//       this._channels = {};
//       this._channelCreate = function (c) {
//           if (_this._debug)
//               console.log("CHANNEL " + c + " CREATED! ");
//           _this._channels[c] = channel.create(c);
//       };
//       this._channelDelete = function (c) {
//           delete _this._channels[c];
//           if (_this._debug)
//               console.log("CHANNEL " + c + " DELETED! ");
//       };
//       this._channelSubscribe = function (c, f) {
//           var channel = _this._channels[c];
//           channel.subscribe(f);
//           if (_this._debug)
//               console.log("CHANNEL " + c + " SUBSCRIBED! " + channel.numHandlers);
//           return channel.numHandlers;
//       };
//       this._channelUnsubscribe = function (c, f) {
//           var channel = _this._channels[c];
//           channel.unsubscribe(f);
//           if (_this._debug)
//               console.log("CHANNEL " + c + " UNSUBSCRIBED! " + channel.numHandlers);
//           return channel.numHandlers;
//       };
//       this._channelFire = function (event) {
//           if (_this._debug)
//               console.log("CHANNEL " + event.type + " FIRED! ");
//           _this._channels[event.type].fire(event);
//       };
//       this._channelExists = function (c) {
//           return _this._channels.hasOwnProperty(c);
//       };
//   }
//   /**
//    * fire native evet
//    *
//    * @param type
//    * @param globalFlagOrData
//    * @param data
//    * @param success
//    * @param error
//    */
//   Broadcaster.prototype.fireNativeEvent = function (type, globalFlagOrData, data, success, error) {
//       var isGlobal = false;
//       var oData = null;
//       if (typeof globalFlagOrData === 'boolean') {
//           isGlobal = globalFlagOrData;
//           oData = data !== null && data !== void 0 ? data : null;
//       }
//       else if (typeof globalFlagOrData === 'object') {
//           oData = globalFlagOrData;
//       }
//       //function instanceOfAndroidData( object:any ): object is AndroidData {
//       //  return ( 'extras' in object && 'flags' in object && 'category' in object )
//       //}
//       //if( oData!=null && this._instanceOfAndroidData(oData) ) {
//       //  return exec(success, error, "broadcaster", "fireNativeEvent", [ type, oData.extras, isGlobal, oData.flags, oData.category ]);
//       //}
//       exec(success, error, "PushNotification", "fireNativeEvent", [type, oData, isGlobal]);
//   };
//   /**
//    * fire local event
//    *
//    * @param type
//    * @param data
//    */
//   Broadcaster.prototype.fireEvent = function (type, data) {
//       if (!this._channelExists(type))
//           return;
//       var event = document.createEvent('Event');
//       event.initEvent(type, false, false);
//       if (data) {
//           for (var i in data) {
//               if (data.hasOwnProperty(i)) {
//                   event[i] = data[i];
//               }
//           }
//       }
//       this._channelFire(event);
//   };
//   /**
//    * add a listener
//    *
//    * @param eventname
//    * @param globalFlagOrListener
//    * @param listener
//    */
//   Broadcaster.prototype.addEventListener = function (eventname, globalFlagOrListener, listener) {
//       var _this = this;
//       var isGlobal = false;
//       var f = function () { };
//       if (typeof globalFlagOrListener === 'boolean') {
//           isGlobal = globalFlagOrListener;
//           if (!listener)
//               throw "listener must be defined!";
//           f = listener;
//       }
//       else if (typeof globalFlagOrListener === 'function') {
//           f = globalFlagOrListener;
//       }
//       if (!this._channelExists(eventname)) {
//           this._channelCreate(eventname);
//           exec(function () { return _this._channelSubscribe(eventname, f); }, function (err) { return console.log("ERROR addEventListener: ", err); }, "PushNotification", "addEventListener", [eventname, isGlobal]);
//       }
//       else {
//           this._channelSubscribe(eventname, f);
//       }
//   };
//   /**
//    * remove a listener
//    *
//    * @param eventname
//    * @param listener
//    */
//   Broadcaster.prototype.removeEventListener = function (eventname, listener) {
//       var _this = this;
//       if (this._channelExists(eventname)) {
//           if (this._channelUnsubscribe(eventname, listener) === 0) {
//               exec(function () { return _this._channelDelete(eventname); }, function (err) { return console.log("ERROR removeEventListener: ", err); }, "PushNotification", "removeEventListener", [eventname]);
//           }
//       }
//   };
//   return Broadcaster;
// }());
// module.exports = new Broadcaster();