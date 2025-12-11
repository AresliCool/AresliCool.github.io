System.register("chunks:///_virtual/aes.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './cipher-core.ts'], function (exports) {
  var _inheritsLoose, cclegacy, BlockCipher;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      BlockCipher = module.BlockCipher;
    }],
    execute: function () {
      cclegacy._RF.push({}, "fa3bdY6psFJ75al0Jt92HI2", "aes", undefined);

      // Lookup tables
      var _SBOX = [];
      var INV_SBOX = [];
      var _SUB_MIX_0 = [];
      var _SUB_MIX_1 = [];
      var _SUB_MIX_2 = [];
      var _SUB_MIX_3 = [];
      var INV_SUB_MIX_0 = [];
      var INV_SUB_MIX_1 = [];
      var INV_SUB_MIX_2 = [];
      var INV_SUB_MIX_3 = [];

      // Compute lookup tables

      // Compute double table
      var d = [];
      for (var i = 0; i < 256; i += 1) {
        if (i < 128) {
          d[i] = i << 1;
        } else {
          d[i] = i << 1 ^ 0x11b;
        }
      }

      // Walk GF(2^8)
      var x = 0;
      var xi = 0;
      for (var _i = 0; _i < 256; _i += 1) {
        // Compute sbox
        var sx = xi ^ xi << 1 ^ xi << 2 ^ xi << 3 ^ xi << 4;
        sx = sx >>> 8 ^ sx & 0xff ^ 0x63;
        _SBOX[x] = sx;
        INV_SBOX[sx] = x;

        // Compute multiplication
        var x2 = d[x];
        var x4 = d[x2];
        var x8 = d[x4];

        // Compute sub bytes, mix columns tables
        var t = d[sx] * 0x101 ^ sx * 0x1010100;
        _SUB_MIX_0[x] = t << 24 | t >>> 8;
        _SUB_MIX_1[x] = t << 16 | t >>> 16;
        _SUB_MIX_2[x] = t << 8 | t >>> 24;
        _SUB_MIX_3[x] = t;

        // Compute inv sub bytes, inv mix columns tables
        t = x8 * 0x1010101 ^ x4 * 0x10001 ^ x2 * 0x101 ^ x * 0x1010100;
        INV_SUB_MIX_0[sx] = t << 24 | t >>> 8;
        INV_SUB_MIX_1[sx] = t << 16 | t >>> 16;
        INV_SUB_MIX_2[sx] = t << 8 | t >>> 24;
        INV_SUB_MIX_3[sx] = t;

        // Compute next counter
        if (!x) {
          xi = 1;
          x = xi;
        } else {
          x = x2 ^ d[d[d[x8 ^ x2]]];
          xi ^= d[d[xi]];
        }
      }

      // Precomputed Rcon lookup
      var RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

      /**
       * AES block cipher algorithm.
       */
      var AESAlgo = exports('AESAlgo', /*#__PURE__*/function (_BlockCipher) {
        _inheritsLoose(AESAlgo, _BlockCipher);
        function AESAlgo() {
          return _BlockCipher.apply(this, arguments) || this;
        }
        var _proto = AESAlgo.prototype;
        _proto._doReset = function _doReset() {
          var t;

          // Skip reset of nRounds has been set before and key did not change
          if (this._nRounds && this._keyPriorReset === this._key) {
            return;
          }

          // Shortcuts
          this._keyPriorReset = this._key;
          var key = this._keyPriorReset;
          var keyWords = key.words;
          var keySize = key.sigBytes / 4;

          // Compute number of rounds
          this._nRounds = keySize + 6;
          var nRounds = this._nRounds;

          // Compute number of key schedule rows
          var ksRows = (nRounds + 1) * 4;

          // Compute key schedule
          this._keySchedule = [];
          var keySchedule = this._keySchedule;
          for (var ksRow = 0; ksRow < ksRows; ksRow += 1) {
            if (ksRow < keySize) {
              keySchedule[ksRow] = keyWords[ksRow];
            } else {
              t = keySchedule[ksRow - 1];
              if (!(ksRow % keySize)) {
                // Rot word
                t = t << 8 | t >>> 24;

                // Sub word
                t = _SBOX[t >>> 24] << 24 | _SBOX[t >>> 16 & 0xff] << 16 | _SBOX[t >>> 8 & 0xff] << 8 | _SBOX[t & 0xff];

                // Mix Rcon
                t ^= RCON[ksRow / keySize | 0] << 24;
              } else if (keySize > 6 && ksRow % keySize === 4) {
                // Sub word
                t = _SBOX[t >>> 24] << 24 | _SBOX[t >>> 16 & 0xff] << 16 | _SBOX[t >>> 8 & 0xff] << 8 | _SBOX[t & 0xff];
              }
              keySchedule[ksRow] = keySchedule[ksRow - keySize] ^ t;
            }
          }

          // Compute inv key schedule
          this._invKeySchedule = [];
          var invKeySchedule = this._invKeySchedule;
          for (var invKsRow = 0; invKsRow < ksRows; invKsRow += 1) {
            var _ksRow = ksRows - invKsRow;
            if (invKsRow % 4) {
              t = keySchedule[_ksRow];
            } else {
              t = keySchedule[_ksRow - 4];
            }
            if (invKsRow < 4 || _ksRow <= 4) {
              invKeySchedule[invKsRow] = t;
            } else {
              invKeySchedule[invKsRow] = INV_SUB_MIX_0[_SBOX[t >>> 24]] ^ INV_SUB_MIX_1[_SBOX[t >>> 16 & 0xff]] ^ INV_SUB_MIX_2[_SBOX[t >>> 8 & 0xff]] ^ INV_SUB_MIX_3[_SBOX[t & 0xff]];
            }
          }
        };
        _proto.encryptBlock = function encryptBlock(M, offset) {
          this._doCryptBlock(M, offset, this._keySchedule, _SUB_MIX_0, _SUB_MIX_1, _SUB_MIX_2, _SUB_MIX_3, _SBOX);
        };
        _proto.decryptBlock = function decryptBlock(M, offset) {
          var _M = M;

          // Swap 2nd and 4th rows
          var t = _M[offset + 1];
          _M[offset + 1] = _M[offset + 3];
          _M[offset + 3] = t;
          this._doCryptBlock(_M, offset, this._invKeySchedule, INV_SUB_MIX_0, INV_SUB_MIX_1, INV_SUB_MIX_2, INV_SUB_MIX_3, INV_SBOX);

          // Inv swap 2nd and 4th rows
          t = _M[offset + 1];
          _M[offset + 1] = _M[offset + 3];
          _M[offset + 3] = t;
        };
        _proto._doCryptBlock = function _doCryptBlock(M, offset, keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX) {
          var _M = M;

          // Shortcut
          var nRounds = this._nRounds;

          // Get input, add round key
          var s0 = _M[offset] ^ keySchedule[0];
          var s1 = _M[offset + 1] ^ keySchedule[1];
          var s2 = _M[offset + 2] ^ keySchedule[2];
          var s3 = _M[offset + 3] ^ keySchedule[3];

          // Key schedule row counter
          var ksRow = 4;

          // Rounds
          for (var round = 1; round < nRounds; round += 1) {
            // Shift rows, sub bytes, mix columns, add round key
            var _t = SUB_MIX_0[s0 >>> 24] ^ SUB_MIX_1[s1 >>> 16 & 0xff] ^ SUB_MIX_2[s2 >>> 8 & 0xff] ^ SUB_MIX_3[s3 & 0xff] ^ keySchedule[ksRow];
            ksRow += 1;
            var _t2 = SUB_MIX_0[s1 >>> 24] ^ SUB_MIX_1[s2 >>> 16 & 0xff] ^ SUB_MIX_2[s3 >>> 8 & 0xff] ^ SUB_MIX_3[s0 & 0xff] ^ keySchedule[ksRow];
            ksRow += 1;
            var _t3 = SUB_MIX_0[s2 >>> 24] ^ SUB_MIX_1[s3 >>> 16 & 0xff] ^ SUB_MIX_2[s0 >>> 8 & 0xff] ^ SUB_MIX_3[s1 & 0xff] ^ keySchedule[ksRow];
            ksRow += 1;
            var _t4 = SUB_MIX_0[s3 >>> 24] ^ SUB_MIX_1[s0 >>> 16 & 0xff] ^ SUB_MIX_2[s1 >>> 8 & 0xff] ^ SUB_MIX_3[s2 & 0xff] ^ keySchedule[ksRow];
            ksRow += 1;

            // Update state
            s0 = _t;
            s1 = _t2;
            s2 = _t3;
            s3 = _t4;
          }

          // Shift rows, sub bytes, add round key
          var t0 = (SBOX[s0 >>> 24] << 24 | SBOX[s1 >>> 16 & 0xff] << 16 | SBOX[s2 >>> 8 & 0xff] << 8 | SBOX[s3 & 0xff]) ^ keySchedule[ksRow];
          ksRow += 1;
          var t1 = (SBOX[s1 >>> 24] << 24 | SBOX[s2 >>> 16 & 0xff] << 16 | SBOX[s3 >>> 8 & 0xff] << 8 | SBOX[s0 & 0xff]) ^ keySchedule[ksRow];
          ksRow += 1;
          var t2 = (SBOX[s2 >>> 24] << 24 | SBOX[s3 >>> 16 & 0xff] << 16 | SBOX[s0 >>> 8 & 0xff] << 8 | SBOX[s1 & 0xff]) ^ keySchedule[ksRow];
          ksRow += 1;
          var t3 = (SBOX[s3 >>> 24] << 24 | SBOX[s0 >>> 16 & 0xff] << 16 | SBOX[s1 >>> 8 & 0xff] << 8 | SBOX[s2 & 0xff]) ^ keySchedule[ksRow];
          ksRow += 1;

          // Set output
          _M[offset] = t0;
          _M[offset + 1] = t1;
          _M[offset + 2] = t2;
          _M[offset + 3] = t3;
        };
        return AESAlgo;
      }(BlockCipher));
      AESAlgo.keySize = 256 / 32;

      /**
       * Shortcut functions to the cipher's object interface.
       *
       * @example
       *
       *     var ciphertext = CryptoJS.AES.encrypt(message, key, cfg);
       *     var plaintext  = CryptoJS.AES.decrypt(ciphertext, key, cfg);
       */
      var AES = exports('AES', BlockCipher._createHelper(AESAlgo));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/AudioManager.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './ResourceManager.ts'], function (exports) {
  var _createClass, cclegacy, AudioClip, tween, Node, director, AudioSource, ResourceManager;
  return {
    setters: [function (module) {
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
      AudioClip = module.AudioClip;
      tween = module.tween;
      Node = module.Node;
      director = module.director;
      AudioSource = module.AudioSource;
    }, function (module) {
      ResourceManager = module.ResourceManager;
    }],
    execute: function () {
      cclegacy._RF.push({}, "514056SadJHF4eW7pyngh+u", "AudioManager", undefined);
      var AudioManager = exports('AudioManager', /*#__PURE__*/function () {
        function AudioManager() {
          this.music = void 0;
          this.sound = void 0;
          this.musicVolume = 1.0;
          this.soundVolume = 1.0;
          var audioMgr = new Node();
          audioMgr.name = '__audioMgr__';
          director.getScene().addChild(audioMgr);
          director.addPersistRootNode(audioMgr);
          this.music = audioMgr.addComponent(AudioSource);
          this.sound = audioMgr.addComponent(AudioSource);
        }
        var _proto = AudioManager.prototype;
        _proto.playSound = function playSound(sound, loop) {
          if (loop === void 0) {
            loop = false;
          }
          if (sound instanceof AudioClip) {
            this.sound.loop = loop;
            this.sound.playOneShot(sound, this.soundVolume);
          } else {
            var clip = ResourceManager.instance.getAsset(sound, "ab_sounds", AudioClip);
            this.sound.loop = loop;
            this.sound.playOneShot(clip, this.soundVolume);
          }
        };
        _proto.playMusic = function playMusic(sound, loop) {
          if (loop === void 0) {
            loop = true;
          }
          if (sound instanceof AudioClip) {
            this.music.loop = loop;
            this.music.stop();
            this.music.clip = sound;
            this.music.play();
            this.music.volume = this.musicVolume;
          } else {
            var clip = ResourceManager.instance.getAsset(sound, "ab_sounds", AudioClip);
            this.music.loop = loop;
            this.music.stop();
            this.music.clip = clip;
            this.music.play();
            this.music.volume = this.musicVolume;
          }
        };
        _proto.changeMusic = function changeMusic(sound) {
          var _this = this;
          tween(this.music).to(0.3, {
            volume: 0
          }, {
            easing: 'linear'
          }).call(function () {
            _this.playMusic(sound);
            tween(_this.music).to(0.3, {
              volume: _this.musicVolume
            }, {
              easing: 'linear'
            }).start();
          }).start();
        };
        _proto.musicFadeOut = function musicFadeOut() {
          tween(this.music).to(0.5, {
            volume: 0
          }, {
            easing: 'linear'
          }).start();
        };
        _proto.musicFadeIn = function musicFadeIn() {
          tween(this.music).to(0.5, {
            volume: this.musicVolume
          }, {
            easing: 'linear'
          }).start();
        };
        _proto.muteMusic = function muteMusic(value) {
          if (value === void 0) {
            value = 0;
          }
          this.music.volume = this.musicVolume = value;
        };
        _proto.stopMusic = function stopMusic() {
          this.music.stop();
        };
        _proto.pauseMusic = function pauseMusic() {
          this.music.pause();
        };
        _proto.resumeMusic = function resumeMusic() {
          this.music.play();
        };
        _proto.muteSound = function muteSound(value) {
          if (value === void 0) {
            value = 0;
          }
          this.sound.volume = this.soundVolume = value;
        };
        _proto.stopSound = function stopSound() {
          this.sound.stop();
        };
        _proto.pauseSound = function pauseSound() {
          this.sound.pause();
        };
        _proto.resumeSound = function resumeSound() {
          this.sound.play();
        };
        _createClass(AudioManager, null, [{
          key: "instance",
          get: function get() {
            if (this._instance == null) {
              this._instance = new AudioManager();
            }
            return this._instance;
          }
        }]);
        return AudioManager;
      }());
      AudioManager._instance = void 0;
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Backpack.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BackpackGrid.ts', './UserData.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, Prefab, Node, instantiate, Component, BackpackGrid, UserData;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Prefab = module.Prefab;
      Node = module.Node;
      instantiate = module.instantiate;
      Component = module.Component;
    }, function (module) {
      BackpackGrid = module.BackpackGrid;
    }, function (module) {
      UserData = module.UserData;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _class, _class2, _descriptor, _descriptor2;
      cclegacy._RF.push({}, "6683551VZpBObzg0BKax+gt", "Backpack", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var Backpack = exports('Backpack', (_dec = ccclass('Backpack'), _dec2 = property(Prefab), _dec3 = property(Node), _dec(_class = (_class2 = /*#__PURE__*/function (_Component) {
        _inheritsLoose(Backpack, _Component);
        function Backpack() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Component.call.apply(_Component, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "BackpackGridPrefab", _descriptor, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "grids", _descriptor2, _assertThisInitialized(_this));
          _this.gridsCount = 12;
          _this.gridsList = [];
          return _this;
        }
        var _proto = Backpack.prototype;
        _proto.start = function start() {
          var _this2 = this;
          for (var i = 0; i < this.gridsCount; i++) {
            var grid = instantiate(this.BackpackGridPrefab).getComponent(BackpackGrid);
            this.grids.addChild(grid.node);
            this.gridsList.push(grid);
          }
          UserData.instance.backpack.forEach(function (itemId) {
            var grid = _this2.findGrid(itemId);
            if (grid.isEmpty) {
              grid.addItem(itemId);
            }
          });
        }

        //返回
        ;

        _proto.findGrid = function findGrid(itemId) {
          var latestEmpty = null;
          for (var i = 0; i < this.gridsList.length; i++) {
            if (latestEmpty == null && this.gridsList[i].isEmpty) {
              latestEmpty = this.gridsList[i];
            }
            if (this.gridsList[i].itemIcon.itemId == itemId) {
              return this.gridsList[i];
            }
          }
          return latestEmpty;
        };
        _proto.update = function update(deltaTime) {};
        return Backpack;
      }(Component), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "BackpackGridPrefab", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "grids", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      })), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/BackpackGrid.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './ItemIcon.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, Component, ItemIcon;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Component = module.Component;
    }, function (module) {
      ItemIcon = module.ItemIcon;
    }],
    execute: function () {
      var _dec, _dec2, _class, _class2, _descriptor;
      cclegacy._RF.push({}, "32bc5eJB9pKZa2ySYQAyW4E", "BackpackGrid", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var BackpackGrid = exports('BackpackGrid', (_dec = ccclass('BackpackGrid'), _dec2 = property(ItemIcon), _dec(_class = (_class2 = /*#__PURE__*/function (_Component) {
        _inheritsLoose(BackpackGrid, _Component);
        function BackpackGrid() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Component.call.apply(_Component, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "itemIcon", _descriptor, _assertThisInitialized(_this));
          _this.isEmpty = true;
          return _this;
        }
        var _proto = BackpackGrid.prototype;
        _proto.start = function start() {};
        _proto.addItem = function addItem(itemId) {
          this.isEmpty = false;
          this.itemIcon.itemId = itemId;
          this.itemIcon.node.active = true;
        };
        _proto.clearItem = function clearItem() {
          this.isEmpty = true;
          this.itemIcon.clear();
          this.itemIcon.node.active = false;
        };
        _proto.update = function update(deltaTime) {};
        return BackpackGrid;
      }(Component), _descriptor = _applyDecoratedDescriptor(_class2.prototype, "itemIcon", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Bomb.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './Tile.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, CCInteger, Tile;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      CCInteger = module.CCInteger;
    }, function (module) {
      Tile = module.Tile;
    }],
    execute: function () {
      var _dec, _dec2, _class, _class2, _descriptor;
      cclegacy._RF.push({}, "db5ddQgvpdCvameI1fTV/PZ", "Bomb", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var Bomb = exports('Bomb', (_dec = ccclass('Bomb'), _dec2 = property(CCInteger), _dec(_class = (_class2 = /*#__PURE__*/function (_Tile) {
        _inheritsLoose(Bomb, _Tile);
        function Bomb() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Tile.call.apply(_Tile, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "flameId", _descriptor, _assertThisInitialized(_this));
          return _this;
        }
        var _proto = Bomb.prototype;
        _proto.start = function start() {};
        _proto.explode = function explode() {};
        _proto.update = function update(deltaTime) {};
        return Bomb;
      }(Tile), _descriptor = _applyDecoratedDescriptor(_class2.prototype, "flameId", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return 1;
        }
      }), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Bomb200.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './MapManager.ts', './GlobalData.ts', './Bomb.ts', './StateMachine.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, Animation, MapManager, TileType, GlobalData, Bomb, StateMachine;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Animation = module.Animation;
    }, function (module) {
      MapManager = module.MapManager;
    }, function (module) {
      TileType = module.TileType;
      GlobalData = module.GlobalData;
    }, function (module) {
      Bomb = module.Bomb;
    }, function (module) {
      StateMachine = module.StateMachine;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _class, _class2, _descriptor, _descriptor2;
      cclegacy._RF.push({}, "7ac7cb1PB1AwrOqJwBtQgA1", "Bomb200", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var Bomb200 = exports('Bomb200', (_dec = ccclass('Bomb200'), _dec2 = property(Animation), _dec3 = property(StateMachine), _dec(_class = (_class2 = /*#__PURE__*/function (_Bomb) {
        _inheritsLoose(Bomb200, _Bomb);
        function Bomb200() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Bomb.call.apply(_Bomb, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "animation", _descriptor, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "stateMachine", _descriptor2, _assertThisInitialized(_this));
          _this.blockSlideTypes = [TileType.STATIC, TileType.BOMB];
          return _this;
        }
        var _proto = Bomb200.prototype;
        _proto.start = function start() {};
        _proto.flameHit = function flameHit(flame) {
          this.explode();
        };
        _proto.create = function create(player) {
          var row = player.footRow;
          var col = player.footCol;
          this.node.setPosition(col * GlobalData.TILE_WIDTH, row * GlobalData.TILE_HEIGHT);
          MapManager.instance.underMapNode.addChild(this.node);
          this.addToMap();
          this.stateMachine.setStateByName("StateBomb200Idle");

          // this.scheduleOnce(() => {
          //    this.explode();
          // }, 3);

          // let tiles = MapManager.instance.getTiles(this.minRow, this.minCol);
          // tiles.forEach(tile => {
          //     if (tile.type == TileType.FLAME) {
          //         Resolver.instance.resolve(tile, this);
          //     }
          // });
        };

        _proto.explode = function explode() {
          this.stateMachine.setStateByName("StateBomb200Explode");
        };
        _proto.update = function update(deltaTime) {};
        return Bomb200;
      }(Bomb), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "animation", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "stateMachine", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      })), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Bomb200Creator.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './GlobalData.ts', './ResourceManager.ts', './MapManager.ts', './Bomb200.ts'], function (exports) {
  var _createClass, cclegacy, Prefab, instantiate, log, TileType, ResourceManager, MapManager, Bomb200;
  return {
    setters: [function (module) {
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
      Prefab = module.Prefab;
      instantiate = module.instantiate;
      log = module.log;
    }, function (module) {
      TileType = module.TileType;
    }, function (module) {
      ResourceManager = module.ResourceManager;
    }, function (module) {
      MapManager = module.MapManager;
    }, function (module) {
      Bomb200 = module.Bomb200;
    }],
    execute: function () {
      cclegacy._RF.push({}, "5828b1bseJGf6/btd799XrL", "Bomb200Creator", undefined);
      var Bomb200Creator = exports('Bomb200Creator', /*#__PURE__*/function () {
        function Bomb200Creator() {
          this.blockPutList = [TileType.STATIC, TileType.MOVE, TileType.BOMB];
        }
        var _proto = Bomb200Creator.prototype;
        _proto.create = function create(player) {
          var canPut = this.checkPut(player);
          if (canPut) {
            var BombPrefab = ResourceManager.instance.getAsset("others/bombs/" + player.bombId + "/" + player.bombId, "ab_prefabs", Prefab);
            var bomb = instantiate(BombPrefab).getComponent(Bomb200);
            bomb.create(player);
          } else {
            log("不能放...");
          }
        };
        _proto.checkPut = function checkPut(player) {
          var row = player.footRow;
          var col = player.footCol;
          var tiles = MapManager.instance.getTiles(row, col);
          for (var i = 0; i < this.blockPutList.length; i++) {
            if (MapManager.instance.hasType(tiles, this.blockPutList[i])) {
              return false;
            }
          }
          return true;
        };
        _createClass(Bomb200Creator, null, [{
          key: "instance",
          get: function get() {
            if (!Bomb200Creator._instance) {
              Bomb200Creator._instance = new Bomb200Creator();
            }
            return Bomb200Creator._instance;
          }
        }]);
        return Bomb200Creator;
      }());
      Bomb200Creator._instance = null;
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/BombCreator.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './Bomb200Creator.ts'], function (exports) {
  var _createClass, cclegacy, Bomb200Creator;
  return {
    setters: [function (module) {
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      Bomb200Creator = module.Bomb200Creator;
    }],
    execute: function () {
      cclegacy._RF.push({}, "833d4WUH3tJurZyA8op0arN", "BombCreator", undefined);
      var BombCreator = exports('BombCreator', /*#__PURE__*/function () {
        function BombCreator() {}
        var _proto = BombCreator.prototype;
        _proto.create = function create(player) {
          if (player.bombId == 200) {
            Bomb200Creator.instance.create(player);
          }
        };
        _createClass(BombCreator, null, [{
          key: "instance",
          get: function get() {
            if (!BombCreator._instance) {
              BombCreator._instance = new BombCreator();
            }
            return BombCreator._instance;
          }
        }]);
        return BombCreator;
      }());
      BombCreator._instance = null;
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/cipher-core.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './core.ts', './enc-base64.ts', './evpkdf.ts'], function (exports) {
  var _inheritsLoose, cclegacy, BufferedBlockAlgorithm, WordArray, Base, Base64, EvpKDFAlgo;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      BufferedBlockAlgorithm = module.BufferedBlockAlgorithm;
      WordArray = module.WordArray;
      Base = module.Base;
    }, function (module) {
      Base64 = module.Base64;
    }, function (module) {
      EvpKDFAlgo = module.EvpKDFAlgo;
    }],
    execute: function () {
      cclegacy._RF.push({}, "a3df1uCS7NOjIu6uMI8x7hB", "cipher-core", undefined);

      /**
       * Abstract base cipher template.
       *
       * @property {number} keySize This cipher's key size. Default: 4 (128 bits)
       * @property {number} ivSize This cipher's IV size. Default: 4 (128 bits)
       * @property {number} _ENC_XFORM_MODE A constant representing encryption mode.
       * @property {number} _DEC_XFORM_MODE A constant representing decryption mode.
       */
      var Cipher = exports('Cipher', /*#__PURE__*/function (_BufferedBlockAlgorit) {
        _inheritsLoose(Cipher, _BufferedBlockAlgorit);
        /**
         * Initializes a newly created cipher.
         *
         * @param {number} xformMode Either the encryption or decryption transormation mode constant.
         * @param {WordArray} key The key.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @example
         *
         *     const cipher = CryptoJS.algo.AES.create(
         *       CryptoJS.algo.AES._ENC_XFORM_MODE, keyWordArray, { iv: ivWordArray }
         *     );
         */
        function Cipher(xformMode, key, cfg) {
          var _this;
          _this = _BufferedBlockAlgorit.call(this) || this;

          /**
           * Configuration options.
           *
           * @property {WordArray} iv The IV to use for this operation.
           */
          _this.cfg = Object.assign(new Base(), cfg);

          // Store transform mode and key
          _this._xformMode = xformMode;
          _this._key = key;

          // Set initial values
          _this.reset();
          return _this;
        }

        /**
         * Creates this cipher in encryption mode.
         *
         * @param {WordArray} key The key.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {Cipher} A cipher instance.
         *
         * @static
         *
         * @example
         *
         *     const cipher = CryptoJS.algo.AES.createEncryptor(keyWordArray, { iv: ivWordArray });
         */
        Cipher.createEncryptor = function createEncryptor(key, cfg) {
          return this.create(this._ENC_XFORM_MODE, key, cfg);
        }

        /**
         * Creates this cipher in decryption mode.
         *
         * @param {WordArray} key The key.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {Cipher} A cipher instance.
         *
         * @static
         *
         * @example
         *
         *     const cipher = CryptoJS.algo.AES.createDecryptor(keyWordArray, { iv: ivWordArray });
         */;
        Cipher.createDecryptor = function createDecryptor(key, cfg) {
          return this.create(this._DEC_XFORM_MODE, key, cfg);
        }

        /**
         * Creates shortcut functions to a cipher's object interface.
         *
         * @param {Cipher} cipher The cipher to create a helper for.
         *
         * @return {Object} An object with encrypt and decrypt shortcut functions.
         *
         * @static
         *
         * @example
         *
         *     const AES = CryptoJS.lib.Cipher._createHelper(CryptoJS.algo.AES);
         */;
        Cipher._createHelper = function _createHelper(SubCipher) {
          var selectCipherStrategy = function selectCipherStrategy(key) {
            if (typeof key === 'string') {
              return PasswordBasedCipher;
            }
            return SerializableCipher;
          };
          return {
            encrypt: function encrypt(message, key, cfg) {
              return selectCipherStrategy(key).encrypt(SubCipher, message, key, cfg);
            },
            decrypt: function decrypt(ciphertext, key, cfg) {
              return selectCipherStrategy(key).decrypt(SubCipher, ciphertext, key, cfg);
            }
          };
        }

        /**
         * Resets this cipher to its initial state.
         *
         * @example
         *
         *     cipher.reset();
         */;
        var _proto = Cipher.prototype;
        _proto.reset = function reset() {
          // Reset data buffer
          _BufferedBlockAlgorit.prototype.reset.call(this);

          // Perform concrete-cipher logic
          this._doReset();
        }

        /**
         * Adds data to be encrypted or decrypted.
         *
         * @param {WordArray|string} dataUpdate The data to encrypt or decrypt.
         *
         * @return {WordArray} The data after processing.
         *
         * @example
         *
         *     const encrypted = cipher.process('data');
         *     const encrypted = cipher.process(wordArray);
         */;
        _proto.process = function process(dataUpdate) {
          // Append
          this._append(dataUpdate);

          // Process available blocks
          return this._process();
        }

        /**
         * Finalizes the encryption or decryption process.
         * Note that the finalize operation is effectively a destructive, read-once operation.
         *
         * @param {WordArray|string} dataUpdate The final data to encrypt or decrypt.
         *
         * @return {WordArray} The data after final processing.
         *
         * @example
         *
         *     const encrypted = cipher.finalize();
         *     const encrypted = cipher.finalize('data');
         *     const encrypted = cipher.finalize(wordArray);
         */;
        _proto.finalize = function finalize(dataUpdate) {
          // Final data update
          if (dataUpdate) {
            this._append(dataUpdate);
          }

          // Perform concrete-cipher logic
          var finalProcessedData = this._doFinalize();
          return finalProcessedData;
        };
        return Cipher;
      }(BufferedBlockAlgorithm));
      Cipher._ENC_XFORM_MODE = 1;
      Cipher._DEC_XFORM_MODE = 2;
      Cipher.keySize = 128 / 32;
      Cipher.ivSize = 128 / 32;

      /**
       * Abstract base stream cipher template.
       *
       * @property {number} blockSize
       *
       *     The number of 32-bit words this cipher operates on. Default: 1 (32 bits)
       */
      var StreamCipher = exports('StreamCipher', /*#__PURE__*/function (_Cipher) {
        _inheritsLoose(StreamCipher, _Cipher);
        function StreamCipher() {
          var _this2;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this2 = _Cipher.call.apply(_Cipher, [this].concat(args)) || this;
          _this2.blockSize = 1;
          return _this2;
        }
        var _proto2 = StreamCipher.prototype;
        _proto2._doFinalize = function _doFinalize() {
          // Process partial blocks
          var finalProcessedBlocks = this._process(!!'flush');
          return finalProcessedBlocks;
        };
        return StreamCipher;
      }(Cipher));

      /**
       * Abstract base block cipher mode template.
       */
      var BlockCipherMode = exports('BlockCipherMode', /*#__PURE__*/function (_Base) {
        _inheritsLoose(BlockCipherMode, _Base);
        /**
         * Initializes a newly created mode.
         *
         * @param {Cipher} cipher A block cipher instance.
         * @param {Array} iv The IV words.
         *
         * @example
         *
         *     const mode = CryptoJS.mode.CBC.Encryptor.create(cipher, iv.words);
         */
        function BlockCipherMode(cipher, iv) {
          var _this3;
          _this3 = _Base.call(this) || this;
          _this3._cipher = cipher;
          _this3._iv = iv;
          return _this3;
        }

        /**
         * Creates this mode for encryption.
         *
         * @param {Cipher} cipher A block cipher instance.
         * @param {Array} iv The IV words.
         *
         * @static
         *
         * @example
         *
         *     const mode = CryptoJS.mode.CBC.createEncryptor(cipher, iv.words);
         */
        BlockCipherMode.createEncryptor = function createEncryptor(cipher, iv) {
          return this.Encryptor.create(cipher, iv);
        }

        /**
         * Creates this mode for decryption.
         *
         * @param {Cipher} cipher A block cipher instance.
         * @param {Array} iv The IV words.
         *
         * @static
         *
         * @example
         *
         *     const mode = CryptoJS.mode.CBC.createDecryptor(cipher, iv.words);
         */;
        BlockCipherMode.createDecryptor = function createDecryptor(cipher, iv) {
          return this.Decryptor.create(cipher, iv);
        };
        return BlockCipherMode;
      }(Base));
      function xorBlock(words, offset, blockSize) {
        var _words = words;
        var block;

        // Shortcut
        var iv = this._iv;

        // Choose mixing block
        if (iv) {
          block = iv;

          // Remove IV for subsequent blocks
          this._iv = undefined;
        } else {
          block = this._prevBlock;
        }

        // XOR blocks
        for (var i = 0; i < blockSize; i += 1) {
          _words[offset + i] ^= block[i];
        }
      }

      /**
       * Cipher Block Chaining mode.
       */

      /**
       * Abstract base CBC mode.
       */
      var CBC = exports('CBC', /*#__PURE__*/function (_BlockCipherMode) {
        _inheritsLoose(CBC, _BlockCipherMode);
        function CBC() {
          return _BlockCipherMode.apply(this, arguments) || this;
        }
        return CBC;
      }(BlockCipherMode));
      /**
       * CBC encryptor.
       */
      CBC.Encryptor = /*#__PURE__*/function (_CBC) {
        _inheritsLoose(_class, _CBC);
        function _class() {
          return _CBC.apply(this, arguments) || this;
        }
        var _proto3 = _class.prototype;
        /**
         * Processes the data block at offset.
         *
         * @param {Array} words The data words to operate on.
         * @param {number} offset The offset where the block starts.
         *
         * @example
         *
         *     mode.processBlock(data.words, offset);
         */
        _proto3.processBlock = function processBlock(words, offset) {
          // Shortcuts
          var cipher = this._cipher;
          var blockSize = cipher.blockSize;

          // XOR and encrypt
          xorBlock.call(this, words, offset, blockSize);
          cipher.encryptBlock(words, offset);

          // Remember this block to use with next block
          this._prevBlock = words.slice(offset, offset + blockSize);
        };
        return _class;
      }(CBC);
      /**
       * CBC decryptor.
       */
      CBC.Decryptor = /*#__PURE__*/function (_CBC2) {
        _inheritsLoose(_class2, _CBC2);
        function _class2() {
          return _CBC2.apply(this, arguments) || this;
        }
        var _proto4 = _class2.prototype;
        /**
         * Processes the data block at offset.
         *
         * @param {Array} words The data words to operate on.
         * @param {number} offset The offset where the block starts.
         *
         * @example
         *
         *     mode.processBlock(data.words, offset);
         */
        _proto4.processBlock = function processBlock(words, offset) {
          // Shortcuts
          var cipher = this._cipher;
          var blockSize = cipher.blockSize;

          // Remember this block to use with next block
          var thisBlock = words.slice(offset, offset + blockSize);

          // Decrypt and XOR
          cipher.decryptBlock(words, offset);
          xorBlock.call(this, words, offset, blockSize);

          // This block becomes the previous block
          this._prevBlock = thisBlock;
        };
        return _class2;
      }(CBC);

      /**
       * PKCS #5/7 padding strategy.
       */
      var Pkcs7 = exports('Pkcs7', {
        /**
         * Pads data using the algorithm defined in PKCS #5/7.
         *
         * @param {WordArray} data The data to pad.
         * @param {number} blockSize The multiple that the data should be padded to.
         *
         * @static
         *
         * @example
         *
         *     CryptoJS.pad.Pkcs7.pad(wordArray, 4);
         */
        pad: function pad(data, blockSize) {
          // Shortcut
          var blockSizeBytes = blockSize * 4;

          // Count padding bytes
          var nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

          // Create padding word
          var paddingWord = nPaddingBytes << 24 | nPaddingBytes << 16 | nPaddingBytes << 8 | nPaddingBytes;

          // Create padding
          var paddingWords = [];
          for (var i = 0; i < nPaddingBytes; i += 4) {
            paddingWords.push(paddingWord);
          }
          var padding = WordArray.create(paddingWords, nPaddingBytes);

          // Add padding
          data.concat(padding);
        },
        /**
         * Unpads data that had been padded using the algorithm defined in PKCS #5/7.
         *
         * @param {WordArray} data The data to unpad.
         *
         * @static
         *
         * @example
         *
         *     CryptoJS.pad.Pkcs7.unpad(wordArray);
         */
        unpad: function unpad(data) {
          var _data = data;

          // Get number of padding bytes from last byte
          var nPaddingBytes = _data.words[_data.sigBytes - 1 >>> 2] & 0xff;

          // Remove padding
          _data.sigBytes -= nPaddingBytes;
        }
      });

      /**
       * Abstract base block cipher template.
       *
       * @property {number} blockSize
       *
       *    The number of 32-bit words this cipher operates on. Default: 4 (128 bits)
       */
      var BlockCipher = exports('BlockCipher', /*#__PURE__*/function (_Cipher2) {
        _inheritsLoose(BlockCipher, _Cipher2);
        function BlockCipher(xformMode, key, cfg) {
          var _this4;
          /**
           * Configuration options.
           *
           * @property {Mode} mode The block mode to use. Default: CBC
           * @property {Padding} padding The padding strategy to use. Default: Pkcs7
           */
          _this4 = _Cipher2.call(this, xformMode, key, Object.assign({
            mode: CBC,
            padding: Pkcs7
          }, cfg)) || this;
          _this4.blockSize = 128 / 32;
          return _this4;
        }
        var _proto5 = BlockCipher.prototype;
        _proto5.reset = function reset() {
          var modeCreator;

          // Reset cipher
          _Cipher2.prototype.reset.call(this);

          // Shortcuts
          var cfg = this.cfg;
          var iv = cfg.iv,
            mode = cfg.mode;

          // Reset block mode
          if (this._xformMode === this.constructor._ENC_XFORM_MODE) {
            modeCreator = mode.createEncryptor;
          } else /* if (this._xformMode == this._DEC_XFORM_MODE) */{
              modeCreator = mode.createDecryptor;
              // Keep at least one block in the buffer for unpadding
              this._minBufferSize = 1;
            }
          this._mode = modeCreator.call(mode, this, iv && iv.words);
          this._mode.__creator = modeCreator;
        };
        _proto5._doProcessBlock = function _doProcessBlock(words, offset) {
          this._mode.processBlock(words, offset);
        };
        _proto5._doFinalize = function _doFinalize() {
          var finalProcessedBlocks;

          // Shortcut
          var padding = this.cfg.padding;

          // Finalize
          if (this._xformMode === this.constructor._ENC_XFORM_MODE) {
            // Pad data
            padding.pad(this._data, this.blockSize);

            // Process final blocks
            finalProcessedBlocks = this._process(!!'flush');
          } else /* if (this._xformMode == this._DEC_XFORM_MODE) */{
              // Process final blocks
              finalProcessedBlocks = this._process(!!'flush');

              // Unpad data
              padding.unpad(finalProcessedBlocks);
            }
          return finalProcessedBlocks;
        };
        return BlockCipher;
      }(Cipher));

      /**
       * A collection of cipher parameters.
       *
       * @property {WordArray} ciphertext The raw ciphertext.
       * @property {WordArray} key The key to this ciphertext.
       * @property {WordArray} iv The IV used in the ciphering operation.
       * @property {WordArray} salt The salt used with a key derivation function.
       * @property {Cipher} algorithm The cipher algorithm.
       * @property {Mode} mode The block mode used in the ciphering operation.
       * @property {Padding} padding The padding scheme used in the ciphering operation.
       * @property {number} blockSize The block size of the cipher.
       * @property {Format} formatter
       *    The default formatting strategy to convert this cipher params object to a string.
       */
      var CipherParams = exports('CipherParams', /*#__PURE__*/function (_Base2) {
        _inheritsLoose(CipherParams, _Base2);
        /**
         * Initializes a newly created cipher params object.
         *
         * @param {Object} cipherParams An object with any of the possible cipher parameters.
         *
         * @example
         *
         *     var cipherParams = CryptoJS.lib.CipherParams.create({
         *         ciphertext: ciphertextWordArray,
         *         key: keyWordArray,
         *         iv: ivWordArray,
         *         salt: saltWordArray,
         *         algorithm: CryptoJS.algo.AES,
         *         mode: CryptoJS.mode.CBC,
         *         padding: CryptoJS.pad.PKCS7,
         *         blockSize: 4,
         *         formatter: CryptoJS.format.OpenSSL
         *     });
         */
        function CipherParams(cipherParams) {
          var _this5;
          _this5 = _Base2.call(this) || this;
          _this5.mixIn(cipherParams);
          return _this5;
        }

        /**
         * Converts this cipher params object to a string.
         *
         * @param {Format} formatter (Optional) The formatting strategy to use.
         *
         * @return {string} The stringified cipher params.
         *
         * @throws Error If neither the formatter nor the default formatter is set.
         *
         * @example
         *
         *     var string = cipherParams + '';
         *     var string = cipherParams.toString();
         *     var string = cipherParams.toString(CryptoJS.format.OpenSSL);
         */
        var _proto6 = CipherParams.prototype;
        _proto6.toString = function toString(formatter) {
          return (formatter || this.formatter).stringify(this);
        };
        return CipherParams;
      }(Base));

      /**
       * OpenSSL formatting strategy.
       */
      var OpenSSLFormatter = exports('OpenSSLFormatter', {
        /**
         * Converts a cipher params object to an OpenSSL-compatible string.
         *
         * @param {CipherParams} cipherParams The cipher params object.
         *
         * @return {string} The OpenSSL-compatible string.
         *
         * @static
         *
         * @example
         *
         *     var openSSLString = CryptoJS.format.OpenSSL.stringify(cipherParams);
         */
        stringify: function stringify(cipherParams) {
          var wordArray;

          // Shortcuts
          var ciphertext = cipherParams.ciphertext,
            salt = cipherParams.salt;

          // Format
          if (salt) {
            wordArray = WordArray.create([0x53616c74, 0x65645f5f]).concat(salt).concat(ciphertext);
          } else {
            wordArray = ciphertext;
          }
          return wordArray.toString(Base64);
        },
        /**
         * Converts an OpenSSL-compatible string to a cipher params object.
         *
         * @param {string} openSSLStr The OpenSSL-compatible string.
         *
         * @return {CipherParams} The cipher params object.
         *
         * @static
         *
         * @example
         *
         *     var cipherParams = CryptoJS.format.OpenSSL.parse(openSSLString);
         */
        parse: function parse(openSSLStr) {
          var salt;

          // Parse base64
          var ciphertext = Base64.parse(openSSLStr);

          // Shortcut
          var ciphertextWords = ciphertext.words;

          // Test for salt
          if (ciphertextWords[0] === 0x53616c74 && ciphertextWords[1] === 0x65645f5f) {
            // Extract salt
            salt = WordArray.create(ciphertextWords.slice(2, 4));

            // Remove salt from ciphertext
            ciphertextWords.splice(0, 4);
            ciphertext.sigBytes -= 16;
          }
          return CipherParams.create({
            ciphertext: ciphertext,
            salt: salt
          });
        }
      });

      /**
       * A cipher wrapper that returns ciphertext as a serializable cipher params object.
       */
      var SerializableCipher = exports('SerializableCipher', /*#__PURE__*/function (_Base3) {
        _inheritsLoose(SerializableCipher, _Base3);
        function SerializableCipher() {
          return _Base3.apply(this, arguments) || this;
        }
        /**
         * Encrypts a message.
         *
         * @param {Cipher} cipher The cipher algorithm to use.
         * @param {WordArray|string} message The message to encrypt.
         * @param {WordArray} key The key.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {CipherParams} A cipher params object.
         *
         * @static
         *
         * @example
         *
         *     var ciphertextParams = CryptoJS.lib.SerializableCipher
         *       .encrypt(CryptoJS.algo.AES, message, key);
         *     var ciphertextParams = CryptoJS.lib.SerializableCipher
         *       .encrypt(CryptoJS.algo.AES, message, key, { iv: iv });
         *     var ciphertextParams = CryptoJS.lib.SerializableCipher
         *       .encrypt(CryptoJS.algo.AES, message, key, { iv: iv, format: CryptoJS.format.OpenSSL });
         */
        SerializableCipher.encrypt = function encrypt(cipher, message, key, cfg) {
          // Apply config defaults
          var _cfg = Object.assign(new Base(), this.cfg, cfg);

          // Encrypt
          var encryptor = cipher.createEncryptor(key, _cfg);
          var ciphertext = encryptor.finalize(message);

          // Shortcut
          var cipherCfg = encryptor.cfg;

          // Create and return serializable cipher params
          return CipherParams.create({
            ciphertext: ciphertext,
            key: key,
            iv: cipherCfg.iv,
            algorithm: cipher,
            mode: cipherCfg.mode,
            padding: cipherCfg.padding,
            blockSize: encryptor.blockSize,
            formatter: _cfg.format
          });
        }

        /**
         * Decrypts serialized ciphertext.
         *
         * @param {Cipher} cipher The cipher algorithm to use.
         * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
         * @param {WordArray} key The key.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {WordArray} The plaintext.
         *
         * @static
         *
         * @example
         *
         *     var plaintext = CryptoJS.lib.SerializableCipher
         *       .decrypt(CryptoJS.algo.AES, formattedCiphertext, key,
         *         { iv: iv, format: CryptoJS.format.OpenSSL });
         *     var plaintext = CryptoJS.lib.SerializableCipher
         *       .decrypt(CryptoJS.algo.AES, ciphertextParams, key,
         *         { iv: iv, format: CryptoJS.format.OpenSSL });
         */;
        SerializableCipher.decrypt = function decrypt(cipher, ciphertext, key, cfg) {
          var _ciphertext = ciphertext;

          // Apply config defaults
          var _cfg = Object.assign(new Base(), this.cfg, cfg);

          // Convert string to CipherParams
          _ciphertext = this._parse(_ciphertext, _cfg.format);

          // Decrypt
          var plaintext = cipher.createDecryptor(key, _cfg).finalize(_ciphertext.ciphertext);
          return plaintext;
        }

        /**
         * Converts serialized ciphertext to CipherParams,
         * else assumed CipherParams already and returns ciphertext unchanged.
         *
         * @param {CipherParams|string} ciphertext The ciphertext.
         * @param {Formatter} format The formatting strategy to use to parse serialized ciphertext.
         *
         * @return {CipherParams} The unserialized ciphertext.
         *
         * @static
         *
         * @example
         *
         *     var ciphertextParams = CryptoJS.lib.SerializableCipher
         *       ._parse(ciphertextStringOrParams, format);
         */;
        SerializableCipher._parse = function _parse(ciphertext, format) {
          if (typeof ciphertext === 'string') {
            return format.parse(ciphertext, this);
          }
          return ciphertext;
        };
        return SerializableCipher;
      }(Base));
      /**
       * Configuration options.
       *
       * @property {Formatter} format
       *
       *    The formatting strategy to convert cipher param objects to and from a string.
       *    Default: OpenSSL
       */
      SerializableCipher.cfg = Object.assign(new Base(), {
        format: OpenSSLFormatter
      });

      /**
       * OpenSSL key derivation function.
       */
      var OpenSSLKdf = exports('OpenSSLKdf', {
        /**
         * Derives a key and IV from a password.
         *
         * @param {string} password The password to derive from.
         * @param {number} keySize The size in words of the key to generate.
         * @param {number} ivSize The size in words of the IV to generate.
         * @param {WordArray|string} salt
         *     (Optional) A 64-bit salt to use. If omitted, a salt will be generated randomly.
         *
         * @return {CipherParams} A cipher params object with the key, IV, and salt.
         *
         * @static
         *
         * @example
         *
         *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32);
         *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32, 'saltsalt');
         */
        execute: function execute(password, keySize, ivSize, salt, hasher) {
          var _salt = salt;

          // Generate random salt
          if (!_salt) {
            _salt = WordArray.random(64 / 8);
          }

          // Derive key and IV
          var key;
          if (!hasher) {
            key = EvpKDFAlgo.create({
              keySize: keySize + ivSize
            }).compute(password, _salt);
          } else {
            key = EvpKDFAlgo.create({
              keySize: keySize + ivSize,
              hasher: hasher
            }).compute(password, _salt);
          }

          // Separate key and IV
          var iv = WordArray.create(key.words.slice(keySize), ivSize * 4);
          key.sigBytes = keySize * 4;

          // Return params
          return CipherParams.create({
            key: key,
            iv: iv,
            salt: _salt
          });
        }
      });

      /**
       * A serializable cipher wrapper that derives the key from a password,
       * and returns ciphertext as a serializable cipher params object.
       */
      var PasswordBasedCipher = exports('PasswordBasedCipher', /*#__PURE__*/function (_SerializableCipher) {
        _inheritsLoose(PasswordBasedCipher, _SerializableCipher);
        function PasswordBasedCipher() {
          return _SerializableCipher.apply(this, arguments) || this;
        }
        /**
         * Encrypts a message using a password.
         *
         * @param {Cipher} cipher The cipher algorithm to use.
         * @param {WordArray|string} message The message to encrypt.
         * @param {string} password The password.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {CipherParams} A cipher params object.
         *
         * @static
         *
         * @example
         *
         *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher
         *       .encrypt(CryptoJS.algo.AES, message, 'password');
         *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher
         *       .encrypt(CryptoJS.algo.AES, message, 'password', { format: CryptoJS.format.OpenSSL });
         */
        PasswordBasedCipher.encrypt = function encrypt(cipher, message, password, cfg) {
          // Apply config defaults
          var _cfg = Object.assign(new Base(), this.cfg, cfg);

          // Derive key and other params
          var derivedParams = _cfg.kdf.execute(password, cipher.keySize, cipher.ivSize, _cfg.salt, _cfg.hasher);

          // Add IV to config
          _cfg.iv = derivedParams.iv;

          // Encrypt
          var ciphertext = SerializableCipher.encrypt.call(this, cipher, message, derivedParams.key, _cfg);

          // Mix in derived params
          ciphertext.mixIn(derivedParams);
          return ciphertext;
        }

        /**
         * Decrypts serialized ciphertext using a password.
         *
         * @param {Cipher} cipher The cipher algorithm to use.
         * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
         * @param {string} password The password.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {WordArray} The plaintext.
         *
         * @static
         *
         * @example
         *
         *     var plaintext = CryptoJS.lib.PasswordBasedCipher
         *       .decrypt(CryptoJS.algo.AES, formattedCiphertext, 'password',
         *         { format: CryptoJS.format.OpenSSL });
         *     var plaintext = CryptoJS.lib.PasswordBasedCipher
         *       .decrypt(CryptoJS.algo.AES, ciphertextParams, 'password',
         *         { format: CryptoJS.format.OpenSSL });
         */;
        PasswordBasedCipher.decrypt = function decrypt(cipher, ciphertext, password, cfg) {
          var _ciphertext = ciphertext;

          // Apply config defaults
          var _cfg = Object.assign(new Base(), this.cfg, cfg);

          // Convert string to CipherParams
          _ciphertext = this._parse(_ciphertext, _cfg.format);

          // Derive key and other params
          var derivedParams = _cfg.kdf.execute(password, cipher.keySize, cipher.ivSize, _ciphertext.salt, _cfg.hasher);

          // Add IV to config
          _cfg.iv = derivedParams.iv;

          // Decrypt
          var plaintext = SerializableCipher.decrypt.call(this, cipher, _ciphertext, derivedParams.key, _cfg);
          return plaintext;
        };
        return PasswordBasedCipher;
      }(SerializableCipher));
      /**
       * Configuration options.
       *
       * @property {KDF} kdf
       *     The key derivation function to use to generate a key and IV from a password.
       *     Default: OpenSSL
       */
      PasswordBasedCipher.cfg = Object.assign(SerializableCipher.cfg, {
        kdf: OpenSSLKdf
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/ConfigRole.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './GlobalData.ts', './ResourceManager.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, Sprite, SpriteFrame, Component, PlayerSlotType, ResourceManager;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Sprite = module.Sprite;
      SpriteFrame = module.SpriteFrame;
      Component = module.Component;
    }, function (module) {
      PlayerSlotType = module.PlayerSlotType;
    }, function (module) {
      ResourceManager = module.ResourceManager;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _class, _class2, _descriptor, _descriptor2;
      cclegacy._RF.push({}, "9e5b8JGLcBHY6K9HjdlSOXW", "ConfigRole", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var ConfigRole = exports('ConfigRole', (_dec = ccclass('ConfigRole'), _dec2 = property(Sprite), _dec3 = property(Sprite), _dec(_class = (_class2 = /*#__PURE__*/function (_Component) {
        _inheritsLoose(ConfigRole, _Component);
        function ConfigRole() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Component.call.apply(_Component, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "capSprite", _descriptor, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "coatSprite", _descriptor2, _assertThisInitialized(_this));
          return _this;
        }
        var _proto = ConfigRole.prototype;
        _proto.start = function start() {};
        _proto.setAvatar = function setAvatar(type, avatarId) {
          switch (type) {
            case PlayerSlotType.CAP:
              this.loadAvatar(this.capSprite, avatarId);
              break;
            case PlayerSlotType.COAT:
              this.loadAvatar(this.coatSprite, avatarId);
              break;
          }
        };
        _proto.loadAvatar = function loadAvatar(avatar, avatarId) {
          var spriteFrame = ResourceManager.instance.getAsset("items/" + avatarId + "/spriteFrame", "ab_textures", SpriteFrame);
          if (spriteFrame) {
            avatar.spriteFrame = spriteFrame;
          } else {
            ResourceManager.instance.directLoad("ab_textures", "items/" + avatarId + "/spriteFrame", false, SpriteFrame, function (err, spriteFrame) {
              if (err) {
                console.log(err);
              } else {
                avatar.spriteFrame = spriteFrame;
              }
            });
          }
        };
        _proto.update = function update(deltaTime) {};
        return ConfigRole;
      }(Component), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "capSprite", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "coatSprite", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      })), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/core.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc'], function (exports) {
  var _inheritsLoose, _construct, cclegacy;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
      _construct = module.construct;
    }, function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      var _ref, _ref2, _ref3, _ref4, _ref5;
      cclegacy._RF.push({}, "2715b80bCBPHbVoFR87BiiE", "core", undefined);
      /* eslint-disable no-use-before-define */

      var crypto = ((_ref = typeof globalThis != 'undefined' ? globalThis : void 0) == null ? void 0 : _ref.crypto) || ((_ref2 = typeof global != 'undefined' ? global : void 0) == null ? void 0 : _ref2.crypto) || ((_ref3 = typeof window != 'undefined' ? window : void 0) == null ? void 0 : _ref3.crypto) || ((_ref4 = typeof self != 'undefined' ? self : void 0) == null ? void 0 : _ref4.crypto) || ((_ref5 = typeof frames != 'undefined' ? frames : void 0) == null || (_ref5 = _ref5[0]) == null ? void 0 : _ref5.crypto);
      var randomWordArray;
      if (crypto) {
        randomWordArray = function randomWordArray(nBytes) {
          var words = [];
          for (var i = 0; i < nBytes; i += 4) {
            words.push(crypto.getRandomValues(new Uint32Array(1))[0]);
          }
          return new WordArray(words, nBytes);
        };
      } else {
        // Because there is no global crypto property in this context, cryptographically unsafe Math.random() is used.

        randomWordArray = function randomWordArray(nBytes) {
          var words = [];
          var r = function r(m_w) {
            var _m_w = m_w;
            var _m_z = 0x3ade68b1;
            var mask = 0xffffffff;
            return function () {
              _m_z = 0x9069 * (_m_z & 0xFFFF) + (_m_z >> 0x10) & mask;
              _m_w = 0x4650 * (_m_w & 0xFFFF) + (_m_w >> 0x10) & mask;
              var result = (_m_z << 0x10) + _m_w & mask;
              result /= 0x100000000;
              result += 0.5;
              return result * (Math.random() > 0.5 ? 1 : -1);
            };
          };
          for (var i = 0, rcache; i < nBytes; i += 4) {
            var _r = r((rcache || Math.random()) * 0x100000000);
            rcache = _r() * 0x3ade67b7;
            words.push(_r() * 0x100000000 | 0);
          }
          return new WordArray(words, nBytes);
        };
      }

      /**
       * Base class for inheritance.
       */
      var Base = exports('Base', /*#__PURE__*/function () {
        function Base() {}
        /**
         * Extends this object and runs the init method.
         * Arguments to create() will be passed to init().
         *
         * @return {Object} The new object.
         *
         * @static
         *
         * @example
         *
         *     var instance = MyType.create();
         */
        Base.create = function create() {
          for (var _len = arguments.length, args = new Array(_len), _key2 = 0; _key2 < _len; _key2++) {
            args[_key2] = arguments[_key2];
          }
          return _construct(this, args);
        }

        /**
         * Copies properties into this object.
         *
         * @param {Object} properties The properties to mix in.
         *
         * @example
         *
         *     MyType.mixIn({
         *         field: 'value'
         *     });
         */;
        var _proto = Base.prototype;
        _proto.mixIn = function mixIn(properties) {
          return Object.assign(this, properties);
        }

        /**
         * Creates a copy of this object.
         *
         * @return {Object} The clone.
         *
         * @example
         *
         *     var clone = instance.clone();
         */;
        _proto.clone = function clone() {
          var clone = new this.constructor();
          Object.assign(clone, this);
          return clone;
        };
        return Base;
      }());

      /**
       * An array of 32-bit words.
       *
       * @property {Array} words The array of 32-bit words.
       * @property {number} sigBytes The number of significant bytes in this word array.
       */
      var WordArray = exports('WordArray', /*#__PURE__*/function (_Base) {
        _inheritsLoose(WordArray, _Base);
        /**
         * Initializes a newly created word array.
         *
         * @param {Array} words (Optional) An array of 32-bit words.
         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
         *
         * @example
         *
         *     var wordArray = CryptoJS.lib.WordArray.create();
         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607]);
         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607], 6);
         */
        function WordArray(words, sigBytes) {
          var _this;
          if (words === void 0) {
            words = [];
          }
          if (sigBytes === void 0) {
            sigBytes = words.length * 4;
          }
          _this = _Base.call(this) || this;
          var typedArray = words;
          // Convert buffers to uint8
          if (typedArray instanceof ArrayBuffer) {
            typedArray = new Uint8Array(typedArray);
          }

          // Convert other array views to uint8
          if (typedArray instanceof Int8Array || typedArray instanceof Uint8ClampedArray || typedArray instanceof Int16Array || typedArray instanceof Uint16Array || typedArray instanceof Int32Array || typedArray instanceof Uint32Array || typedArray instanceof Float32Array || typedArray instanceof Float64Array) {
            typedArray = new Uint8Array(typedArray.buffer, typedArray.byteOffset, typedArray.byteLength);
          }

          // Handle Uint8Array
          if (typedArray instanceof Uint8Array) {
            // Shortcut
            var typedArrayByteLength = typedArray.byteLength;

            // Extract bytes
            var _words = [];
            for (var i = 0; i < typedArrayByteLength; i += 1) {
              _words[i >>> 2] |= typedArray[i] << 24 - i % 4 * 8;
            }

            // Initialize this word array
            _this.words = _words;
            _this.sigBytes = typedArrayByteLength;
          } else {
            // Else call normal init
            _this.words = words;
            _this.sigBytes = sigBytes;
          }
          return _this;
        }

        /**
         * Creates a word array filled with random bytes.
         *
         * @param {number} nBytes The number of random bytes to generate.
         *
         * @return {WordArray} The random word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.lib.WordArray.random(16);
         */
        var _proto2 = WordArray.prototype;
        /**
         * Converts this word array to a string.
         *
         * @param {Encoder} encoder (Optional) The encoding strategy to use. Default: CryptoJS.enc.Hex
         *
         * @return {string} The stringified word array.
         *
         * @example
         *
         *     var string = wordArray + '';
         *     var string = wordArray.toString();
         *     var string = wordArray.toString(CryptoJS.enc.Utf8);
         */
        _proto2.toString = function toString(encoder) {
          if (encoder === void 0) {
            encoder = Hex;
          }
          return encoder.stringify(this);
        }

        /**
         * Concatenates a word array to this word array.
         *
         * @param {WordArray} wordArray The word array to append.
         *
         * @return {WordArray} This word array.
         *
         * @example
         *
         *     wordArray1.concat(wordArray2);
         */;
        _proto2.concat = function concat(wordArray) {
          // Shortcuts
          var thisWords = this.words;
          var thatWords = wordArray.words;
          var thisSigBytes = this.sigBytes;
          var thatSigBytes = wordArray.sigBytes;

          // Clamp excess bits
          this.clamp();

          // Concat
          if (thisSigBytes % 4) {
            // Copy one byte at a time
            for (var i = 0; i < thatSigBytes; i += 1) {
              var thatByte = thatWords[i >>> 2] >>> 24 - i % 4 * 8 & 0xff;
              thisWords[thisSigBytes + i >>> 2] |= thatByte << 24 - (thisSigBytes + i) % 4 * 8;
            }
          } else {
            // Copy one word at a time
            for (var _i = 0; _i < thatSigBytes; _i += 4) {
              thisWords[thisSigBytes + _i >>> 2] = thatWords[_i >>> 2];
            }
          }
          this.sigBytes += thatSigBytes;

          // Chainable
          return this;
        }

        /**
         * Removes insignificant bits.
         *
         * @example
         *
         *     wordArray.clamp();
         */;
        _proto2.clamp = function clamp() {
          // Shortcuts
          var words = this.words,
            sigBytes = this.sigBytes;

          // Clamp
          words[sigBytes >>> 2] &= 0xffffffff << 32 - sigBytes % 4 * 8;
          words.length = Math.ceil(sigBytes / 4);
        }

        /**
         * Creates a copy of this word array.
         *
         * @return {WordArray} The clone.
         *
         * @example
         *
         *     var clone = wordArray.clone();
         */;
        _proto2.clone = function clone() {
          var clone = _Base.prototype.clone.call(this);
          clone.words = this.words.slice(0);
          return clone;
        };
        return WordArray;
      }(Base));

      /**
       * Hex encoding strategy.
       */
      WordArray.random = randomWordArray;
      var Hex = exports('Hex', {
        /**
         * Converts a word array to a hex string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The hex string.
         *
         * @static
         *
         * @example
         *
         *     var hexString = CryptoJS.enc.Hex.stringify(wordArray);
         */
        stringify: function stringify(wordArray) {
          // Shortcuts
          var words = wordArray.words,
            sigBytes = wordArray.sigBytes;

          // Convert
          var hexChars = [];
          for (var i = 0; i < sigBytes; i += 1) {
            var bite = words[i >>> 2] >>> 24 - i % 4 * 8 & 0xff;
            hexChars.push((bite >>> 4).toString(16));
            hexChars.push((bite & 0x0f).toString(16));
          }
          return hexChars.join('');
        },
        /**
         * Converts a hex string to a word array.
         *
         * @param {string} hexStr The hex string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Hex.parse(hexString);
         */
        parse: function parse(hexStr) {
          // Shortcut
          var hexStrLength = hexStr.length;

          // Convert
          var words = [];
          for (var i = 0; i < hexStrLength; i += 2) {
            words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << 24 - i % 8 * 4;
          }
          return new WordArray(words, hexStrLength / 2);
        }
      });

      /**
       * Latin1 encoding strategy.
       */
      var Latin1 = exports('Latin1', {
        /**
         * Converts a word array to a Latin1 string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The Latin1 string.
         *
         * @static
         *
         * @example
         *
         *     var latin1String = CryptoJS.enc.Latin1.stringify(wordArray);
         */
        stringify: function stringify(wordArray) {
          // Shortcuts
          var words = wordArray.words,
            sigBytes = wordArray.sigBytes;

          // Convert
          var latin1Chars = [];
          for (var i = 0; i < sigBytes; i += 1) {
            var bite = words[i >>> 2] >>> 24 - i % 4 * 8 & 0xff;
            latin1Chars.push(String.fromCharCode(bite));
          }
          return latin1Chars.join('');
        },
        /**
         * Converts a Latin1 string to a word array.
         *
         * @param {string} latin1Str The Latin1 string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Latin1.parse(latin1String);
         */
        parse: function parse(latin1Str) {
          // Shortcut
          var latin1StrLength = latin1Str.length;

          // Convert
          var words = [];
          for (var i = 0; i < latin1StrLength; i += 1) {
            words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << 24 - i % 4 * 8;
          }
          return new WordArray(words, latin1StrLength);
        }
      });

      /**
       * UTF-8 encoding strategy.
       */
      var Utf8 = exports('Utf8', {
        /**
         * Converts a word array to a UTF-8 string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The UTF-8 string.
         *
         * @static
         *
         * @example
         *
         *     var utf8String = CryptoJS.enc.Utf8.stringify(wordArray);
         */
        stringify: function stringify(wordArray) {
          try {
            return decodeURIComponent(escape(Latin1.stringify(wordArray)));
          } catch (e) {
            throw new Error('Malformed UTF-8 data');
          }
        },
        /**
         * Converts a UTF-8 string to a word array.
         *
         * @param {string} utf8Str The UTF-8 string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Utf8.parse(utf8String);
         */
        parse: function parse(utf8Str) {
          return Latin1.parse(unescape(encodeURIComponent(utf8Str)));
        }
      });

      /**
       * Abstract buffered block algorithm template.
       *
       * The property blockSize must be implemented in a concrete subtype.
       *
       * @property {number} _minBufferSize
       *
       *     The number of blocks that should be kept unprocessed in the buffer. Default: 0
       */
      var BufferedBlockAlgorithm = exports('BufferedBlockAlgorithm', /*#__PURE__*/function (_Base2) {
        _inheritsLoose(BufferedBlockAlgorithm, _Base2);
        function BufferedBlockAlgorithm() {
          var _this2;
          _this2 = _Base2.call(this) || this;
          _this2._minBufferSize = 0;
          return _this2;
        }

        /**
         * Resets this block algorithm's data buffer to its initial state.
         *
         * @example
         *
         *     bufferedBlockAlgorithm.reset();
         */
        var _proto3 = BufferedBlockAlgorithm.prototype;
        _proto3.reset = function reset() {
          // Initial values
          this._data = new WordArray();
          this._nDataBytes = 0;
        }

        /**
         * Adds new data to this block algorithm's buffer.
         *
         * @param {WordArray|string} data
         *
         *     The data to append. Strings are converted to a WordArray using UTF-8.
         *
         * @example
         *
         *     bufferedBlockAlgorithm._append('data');
         *     bufferedBlockAlgorithm._append(wordArray);
         */;
        _proto3._append = function _append(data) {
          var m_data = data;

          // Convert string to WordArray, else assume WordArray already
          if (typeof m_data === 'string') {
            m_data = Utf8.parse(m_data);
          }

          // Append
          this._data.concat(m_data);
          this._nDataBytes += m_data.sigBytes;
        }

        /**
         * Processes available data blocks.
         *
         * This method invokes _doProcessBlock(offset), which must be implemented by a concrete subtype.
         *
         * @param {boolean} doFlush Whether all blocks and partial blocks should be processed.
         *
         * @return {WordArray} The processed data.
         *
         * @example
         *
         *     var processedData = bufferedBlockAlgorithm._process();
         *     var processedData = bufferedBlockAlgorithm._process(!!'flush');
         */;
        _proto3._process = function _process(doFlush) {
          var processedWords;

          // Shortcuts
          var data = this._data,
            blockSize = this.blockSize;
          var dataWords = data.words;
          var dataSigBytes = data.sigBytes;
          var blockSizeBytes = blockSize * 4;

          // Count blocks ready
          var nBlocksReady = dataSigBytes / blockSizeBytes;
          if (doFlush) {
            // Round up to include partial blocks
            nBlocksReady = Math.ceil(nBlocksReady);
          } else {
            // Round down to include only full blocks,
            // less the number of blocks that must remain in the buffer
            nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
          }

          // Count words ready
          var nWordsReady = nBlocksReady * blockSize;

          // Count bytes ready
          var nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

          // Process blocks
          if (nWordsReady) {
            for (var offset = 0; offset < nWordsReady; offset += blockSize) {
              // Perform concrete-algorithm logic
              this._doProcessBlock(dataWords, offset);
            }

            // Remove processed words
            processedWords = dataWords.splice(0, nWordsReady);
            data.sigBytes -= nBytesReady;
          }

          // Return processed words
          return new WordArray(processedWords, nBytesReady);
        }

        /**
         * Creates a copy of this object.
         *
         * @return {Object} The clone.
         *
         * @example
         *
         *     var clone = bufferedBlockAlgorithm.clone();
         */;
        _proto3.clone = function clone() {
          var clone = _Base2.prototype.clone.call(this);
          clone._data = this._data.clone();
          return clone;
        };
        return BufferedBlockAlgorithm;
      }(Base));

      /**
       * Abstract hasher template.
       *
       * @property {number} blockSize
       *
       *     The number of 32-bit words this hasher operates on. Default: 16 (512 bits)
       */
      var Hasher = exports('Hasher', /*#__PURE__*/function (_BufferedBlockAlgorit) {
        _inheritsLoose(Hasher, _BufferedBlockAlgorit);
        function Hasher(cfg) {
          var _this3;
          _this3 = _BufferedBlockAlgorit.call(this) || this;
          _this3.blockSize = 512 / 32;

          /**
           * Configuration options.
           */
          _this3.cfg = Object.assign(new Base(), cfg);

          // Set initial values
          _this3.reset();
          return _this3;
        }

        /**
         * Creates a shortcut function to a hasher's object interface.
         *
         * @param {Hasher} SubHasher The hasher to create a helper for.
         *
         * @return {Function} The shortcut function.
         *
         * @static
         *
         * @example
         *
         *     var SHA256 = CryptoJS.lib.Hasher._createHelper(CryptoJS.algo.SHA256);
         */
        Hasher._createHelper = function _createHelper(SubHasher) {
          return function (message, cfg) {
            return new SubHasher(cfg).finalize(message);
          };
        }

        /**
         * Creates a shortcut function to the HMAC's object interface.
         *
         * @param {Hasher} SubHasher The hasher to use in this HMAC helper.
         *
         * @return {Function} The shortcut function.
         *
         * @static
         *
         * @example
         *
         *     var HmacSHA256 = CryptoJS.lib.Hasher._createHmacHelper(CryptoJS.algo.SHA256);
         */;
        Hasher._createHmacHelper = function _createHmacHelper(SubHasher) {
          return function (message, key) {
            return new HMAC(SubHasher, key).finalize(message);
          };
        }

        /**
         * Resets this hasher to its initial state.
         *
         * @example
         *
         *     hasher.reset();
         */;
        var _proto4 = Hasher.prototype;
        _proto4.reset = function reset() {
          // Reset data buffer
          _BufferedBlockAlgorit.prototype.reset.call(this);

          // Perform concrete-hasher logic
          this._doReset();
        }

        /**
         * Updates this hasher with a message.
         *
         * @param {WordArray|string} messageUpdate The message to append.
         *
         * @return {Hasher} This hasher.
         *
         * @example
         *
         *     hasher.update('message');
         *     hasher.update(wordArray);
         */;
        _proto4.update = function update(messageUpdate) {
          // Append
          this._append(messageUpdate);

          // Update the hash
          this._process();

          // Chainable
          return this;
        }

        /**
         * Finalizes the hash computation.
         * Note that the finalize operation is effectively a destructive, read-once operation.
         *
         * @param {WordArray|string} messageUpdate (Optional) A final message update.
         *
         * @return {WordArray} The hash.
         *
         * @example
         *
         *     var hash = hasher.finalize();
         *     var hash = hasher.finalize('message');
         *     var hash = hasher.finalize(wordArray);
         */;
        _proto4.finalize = function finalize(messageUpdate) {
          // Final message update
          if (messageUpdate) {
            this._append(messageUpdate);
          }

          // Perform concrete-hasher logic
          var hash = this._doFinalize();
          return hash;
        };
        return Hasher;
      }(BufferedBlockAlgorithm));

      /**
       * HMAC algorithm.
       */
      var HMAC = exports('HMAC', /*#__PURE__*/function (_Base3) {
        _inheritsLoose(HMAC, _Base3);
        /**
         * Initializes a newly created HMAC.
         *
         * @param {Hasher} SubHasher The hash algorithm to use.
         * @param {WordArray|string} key The secret key.
         *
         * @example
         *
         *     var hmacHasher = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, key);
         */
        function HMAC(SubHasher, key) {
          var _this4;
          _this4 = _Base3.call(this) || this;
          var hasher = new SubHasher();
          _this4._hasher = hasher;

          // Convert string to WordArray, else assume WordArray already
          var _key = key;
          if (typeof _key === 'string') {
            _key = Utf8.parse(_key);
          }

          // Shortcuts
          var hasherBlockSize = hasher.blockSize;
          var hasherBlockSizeBytes = hasherBlockSize * 4;

          // Allow arbitrary length keys
          if (_key.sigBytes > hasherBlockSizeBytes) {
            _key = hasher.finalize(key);
          }

          // Clamp excess bits
          _key.clamp();

          // Clone key for inner and outer pads
          var oKey = _key.clone();
          _this4._oKey = oKey;
          var iKey = _key.clone();
          _this4._iKey = iKey;

          // Shortcuts
          var oKeyWords = oKey.words;
          var iKeyWords = iKey.words;

          // XOR keys with pad constants
          for (var i = 0; i < hasherBlockSize; i += 1) {
            oKeyWords[i] ^= 0x5c5c5c5c;
            iKeyWords[i] ^= 0x36363636;
          }
          oKey.sigBytes = hasherBlockSizeBytes;
          iKey.sigBytes = hasherBlockSizeBytes;

          // Set initial values
          _this4.reset();
          return _this4;
        }

        /**
         * Resets this HMAC to its initial state.
         *
         * @example
         *
         *     hmacHasher.reset();
         */
        var _proto5 = HMAC.prototype;
        _proto5.reset = function reset() {
          // Shortcut
          var hasher = this._hasher;

          // Reset
          hasher.reset();
          hasher.update(this._iKey);
        }

        /**
         * Updates this HMAC with a message.
         *
         * @param {WordArray|string} messageUpdate The message to append.
         *
         * @return {HMAC} This HMAC instance.
         *
         * @example
         *
         *     hmacHasher.update('message');
         *     hmacHasher.update(wordArray);
         */;
        _proto5.update = function update(messageUpdate) {
          this._hasher.update(messageUpdate);

          // Chainable
          return this;
        }

        /**
         * Finalizes the HMAC computation.
         * Note that the finalize operation is effectively a destructive, read-once operation.
         *
         * @param {WordArray|string} messageUpdate (Optional) A final message update.
         *
         * @return {WordArray} The HMAC.
         *
         * @example
         *
         *     var hmac = hmacHasher.finalize();
         *     var hmac = hmacHasher.finalize('message');
         *     var hmac = hmacHasher.finalize(wordArray);
         */;
        _proto5.finalize = function finalize(messageUpdate) {
          // Shortcut
          var hasher = this._hasher;

          // Compute HMAC
          var innerHash = hasher.finalize(messageUpdate);
          hasher.reset();
          var hmac = hasher.finalize(this._oKey.clone().concat(innerHash));
          return hmac;
        };
        return HMAC;
      }(Base));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/CSVManager.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './CSVParser.ts'], function (exports) {
  var _createForOfIteratorHelperLoose, _createClass, cclegacy, CSV;
  return {
    setters: [function (module) {
      _createForOfIteratorHelperLoose = module.createForOfIteratorHelperLoose;
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      CSV = module.CSV;
    }],
    execute: function () {
      cclegacy._RF.push({}, "9a682c7c2ZIb5rLi9LzlD5r", "CSVManager", undefined);
      var CSVManager = exports('CSVManager', /*#__PURE__*/function () {
        function CSVManager() {
          this.csvs = new Map();
        }
        var _proto = CSVManager.prototype;
        _proto.addCSV = function addCSV(name, data) {
          var csv = CSV.parse(data, {
            header: true
          }, null);
          this.csvs.set(name, csv);
          return csv;
        };
        _proto.query = function query(csvName, key, value, isAll) {
          if (isAll === void 0) {
            isAll = false;
          }
          if (!this.csvs.has(csvName)) {
            return null;
          }
          var list = [];
          var csv = this.csvs.get(csvName);
          for (var _iterator = _createForOfIteratorHelperLoose(csv), _step; !(_step = _iterator()).done;) {
            var item = _step.value;
            if (item[key] && item[key] == value) {
              if (!isAll) {
                return item;
              } else {
                list.push(item);
              }
            }
          }
          return isAll ? list : null;
        };
        _createClass(CSVManager, null, [{
          key: "instance",
          get: function get() {
            if (!CSVManager._instance) {
              CSVManager._instance = new CSVManager();
            }
            return CSVManager._instance;
          }
        }]);
        return CSVManager;
      }());
      // casts:Map<string, any> = new Map();
      // opts:Map<string, any> = new Map();
      CSVManager._instance = null;
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/CSVParser.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "80e47FBD1xKs7vOLQd+iSbU", "CSVParser", undefined);
      var CELL_DELIMITERS = [",", ";", "\t", "|", "^"];
      var LINE_DELIMITERS = ["\r\n", "\r", "\n"];
      var getterCast = function getterCast(value, index, cast, d) {
        if (cast instanceof Array) {
          if (cast[index] === "number") {
            return Number(d[index]);
          } else if (cast[index] === "boolean") {
            return d[index] === "true" || d[index] === "t" || d[index] === "1";
          } else {
            return d[index];
          }
        } else {
          if (!isNaN(Number(value))) {
            return Number(d[index]);
          } else if (value == "false" || value == "true" || value == "t" || value == "f") {
            return d[index] === "true" || d[index] === "t" || d[index] === "1";
          } else {
            return d[index];
          }
        }
      };
      var CSV = exports('CSV', {
        //

        /* =========================================
            * Constants ===============================
            * ========================================= */

        STANDARD_DECODE_OPTS: {
          skip: 0,
          limit: false,
          header: false,
          cast: false,
          comment: ""
        },
        STANDARD_ENCODE_OPTS: {
          delimiter: CELL_DELIMITERS[0],
          newline: LINE_DELIMITERS[0],
          skip: 0,
          limit: false,
          header: false
        },
        quoteMark: '"',
        doubleQuoteMark: '""',
        quoteRegex: /"/g,
        /* =========================================
            * Utility Functions =======================
            * ========================================= */
        assign: function assign() {
          var args = Array.prototype.slice.call(arguments);
          var base = args[0];
          var rest = args.slice(1);
          for (var i = 0, len = rest.length; i < len; i++) {
            for (var attr in rest[i]) {
              base[attr] = rest[i][attr];
            }
          }
          return base;
        },
        map: function map(collection, fn) {
          var results = [];
          for (var i = 0, len = collection.length; i < len; i++) {
            results[i] = fn(collection[i], i);
          }
          return results;
        },
        getType: function getType(obj) {
          return Object.prototype.toString.call(obj).slice(8, -1);
        },
        getLimit: function getLimit(limit, len) {
          return limit === false ? len : limit;
        },
        buildObjectConstructor: function buildObjectConstructor(fields, sample, cast) {
          return function (d) {
            var object = new Object();
            var setter = function setter(attr, value) {
              return object[attr] = value;
            };
            if (cast) {
              fields.forEach(function (attr, idx) {
                setter(attr, getterCast(sample[idx], idx, cast, d));
              });
            } else {
              fields.forEach(function (attr, idx) {
                setter(attr, getterCast(sample[idx], idx, null, d));
              });
            }
            // body.push("return object;");
            // body.join(";\n");
            return object;
          };
        },
        buildArrayConstructor: function buildArrayConstructor(fields, sample, cast) {
          return function (d) {
            var row = new Array(sample.length);
            var setter = function setter(idx, value) {
              return row[idx] = value;
            };
            if (cast) {
              fields.forEach(function (attr, idx) {
                setter(attr, getterCast(sample[idx], idx, cast, d));
              });
            } else {
              fields.forEach(function (attr, idx) {
                setter(attr, getterCast(sample[idx], idx, null, d));
              });
            }
            return row;
          };
        },
        frequency: function frequency(coll, needle, limit) {
          if (limit === void 0) limit = false;
          var count = 0;
          var lastIndex = 0;
          var maxIndex = this.getLimit(limit, coll.length);
          while (lastIndex < maxIndex) {
            lastIndex = coll.indexOf(needle, lastIndex);
            if (lastIndex === -1) break;
            lastIndex += 1;
            count++;
          }
          return count;
        },
        mostFrequent: function mostFrequent(coll, needles, limit) {
          var max = 0;
          var detected;
          for (var cur = needles.length - 1; cur >= 0; cur--) {
            if (this.frequency(coll, needles[cur], limit) > max) {
              detected = needles[cur];
            }
          }
          return detected || needles[0];
        },
        unsafeParse: function unsafeParse(text, opts, fn) {
          var lines = text.split(opts.newline);
          if (opts.skip > 0) {
            lines.splice(opts.skip);
          }
          var fields;
          var constructor;
          function cells(lines) {
            var line = lines.shift();
            if (line.indexOf('"') >= 0) {
              // 含引号

              // 找到这行完整的数据, 找到对称的双引号
              var lastIndex = 0;
              var findIndex = 0;
              var count = 0;
              while (lines.length > 0) {
                lastIndex = line.indexOf('"', findIndex);
                if (lastIndex === -1 && count % 2 === 0) break;
                if (lastIndex !== -1) {
                  findIndex = lastIndex + 1;
                  count++;
                } else {
                  line = line + opts.newline + lines.shift();
                }
              }
              var list = [];
              var item;
              var quoteCount = 0;
              var start = 0;
              var end = 0;
              var length = line.length;
              for (var key in line) {
                if (!line.hasOwnProperty(key)) {
                  continue;
                }
                var numKey = parseInt(key);
                var value = line[key];
                if (numKey === 0 && value === '"') {
                  quoteCount++;
                  start = 1;
                }
                if (value === '"') {
                  quoteCount++;
                  if (line[numKey - 1] === opts.delimiter && start === numKey) {
                    start++;
                  }
                }
                if (value === '"' && quoteCount % 2 === 0) {
                  if (line[numKey + 1] === opts.delimiter || numKey + 1 === length) {
                    end = numKey;
                    item = line.substring(start, end);
                    list.push(item);
                    start = end + 2;
                    end = start;
                  }
                }
                if (value === opts.delimiter && quoteCount % 2 === 0) {
                  end = numKey;
                  if (end > start) {
                    item = line.substring(start, end);
                    list.push(item);
                    start = end + 1;
                    end = start;
                  } else if (end === start) {
                    list.push("");
                    start = end + 1;
                    end = start;
                  }
                }
              }
              end = length;
              if (end >= start) {
                item = line.substring(start, end);
                list.push(item);
              }
              return list;
            } else {
              return line.split(opts.delimiter);
            }
          }
          if (opts.header) {
            if (opts.header === true) {
              opts.comment = cells(lines);
              opts.cast = cells(lines);
              fields = cells(lines);
            } else if (this.getType(opts.header) === "Array") {
              fields = opts.header;
            }
            constructor = this.buildObjectConstructor(fields, lines[0].split(opts.delimiter), opts.cast);
          } else {
            constructor = this.buildArrayConstructor(fields, lines[0].split(opts.delimiter), opts.cast);
          }
          while (lines.length > 0) {
            var row = cells(lines);
            if (row.length > 1) {
              fn(constructor(row), fields[0]);
            }
          }
          return true;
        },
        safeParse: function safeParse(text, opts, fn) {
          var delimiter = opts.delimiter;
          var newline = opts.newline;
          var lines = text.split(newline);
          if (opts.skip > 0) {
            lines.splice(opts.skip);
          }
          return true;
        },
        encodeCells: function encodeCells(line, delimiter, newline) {
          var row = line.slice(0);
          for (var i = 0, len = row.length; i < len; i++) {
            if (row[i].indexOf(this.quoteMark) !== -1) {
              row[i] = row[i].replace(this.quoteRegex, this.doubleQuoteMark);
            }
            if (row[i].indexOf(delimiter) !== -1 || row[i].indexOf(newline) !== -1) {
              row[i] = this.quoteMark + row[i] + this.quoteMark;
            }
          }
          return row.join(delimiter);
        },
        encodeArrays: function encodeArrays(coll, opts, fn) {
          var delimiter = opts.delimiter;
          var newline = opts.newline;
          if (opts.header && this.getType(opts.header) === "Array") {
            fn(this.encodeCells(opts.header, delimiter, newline));
          }
          for (var cur = 0, lim = this.getLimit(opts.limit, coll.length); cur < lim; cur++) {
            fn(this.encodeCells(coll[cur], delimiter, newline));
          }
          return true;
        },
        encodeObjects: function encodeObjects(coll, opts, fn) {
          var delimiter = opts.delimiter;
          var newline = opts.newline;
          var header;
          var row;
          header = [];
          row = [];
          for (var key in coll[0]) {
            header.push(key);
            row.push(coll[0][key]);
          }
          if (opts.header === true) {
            fn(this.encodeCells(header, delimiter, newline));
          } else if (this.getType(opts.header) === "Array") {
            fn(this.encodeCells(opts.header, delimiter, newline));
          }
          fn(this.encodeCells(row, delimiter));
          for (var cur = 1, lim = this.getLimit(opts.limit, coll.length); cur < lim; cur++) {
            row = [];
            for (var key$1 = 0, len = header.length; key$1 < len; key$1++) {
              row.push(coll[cur][header[key$1]]);
            }
            fn(this.encodeCells(row, delimiter, newline));
          }
          return true;
        },
        parse: function parse(text, opts, fn) {
          var rows;
          if (this.getType(opts) === "Function") {
            fn = opts;
            opts = {};
          } else if (this.getType(fn) !== "Function") {
            rows = [];
            fn = rows.push.bind(rows);
          } else {
            rows = [];
          }
          opts = this.assign({}, this.STANDARD_DECODE_OPTS, opts);
          this.opts = opts;
          if (!opts.delimiter || !opts.newline) {
            var limit = Math.min(48, Math.floor(text.length / 20), text.length);
            opts.delimiter = opts.delimiter || this.mostFrequent(text, CELL_DELIMITERS, limit);
            opts.newline = opts.newline || this.mostFrequent(text, LINE_DELIMITERS, limit);
          }

          // modify by jl 由表自行控制不要含有双引号.提高解析效率
          return this.unsafeParse(text, opts, fn) && (rows.length > 0 ? rows : true);
        },
        encode: function encode(coll, opts, fn) {
          var lines;
          if (this.getType(opts) === "Function") {
            fn = opts;
            opts = {};
          } else if (this.getType(fn) !== "Function") {
            lines = [];
            fn = lines.push.bind(lines);
          }
          opts = this.assign({}, this.STANDARD_ENCODE_OPTS, opts);
          if (opts.skip > 0) {
            coll = coll.slice(opts.skip);
          }
          return (this.getType(coll[0]) === "Array" ? this.encodeArrays : this.encodeObjects)(coll, opts, fn) && (lines.length > 0 ? lines.join(opts.newline) : true);
        }
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/enc-base64.ts", ['cc', './core.ts'], function (exports) {
  var cclegacy, WordArray;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      WordArray = module.WordArray;
    }],
    execute: function () {
      cclegacy._RF.push({}, "85919SItgVOFL1+j1cCFDjj", "enc-base64", undefined);
      var parseLoop = exports('parseLoop', function parseLoop(base64Str, base64StrLength, reverseMap) {
        var words = [];
        var nBytes = 0;
        for (var i = 0; i < base64StrLength; i += 1) {
          if (i % 4) {
            var bits1 = reverseMap[base64Str.charCodeAt(i - 1)] << i % 4 * 2;
            var bits2 = reverseMap[base64Str.charCodeAt(i)] >>> 6 - i % 4 * 2;
            var bitsCombined = bits1 | bits2;
            words[nBytes >>> 2] |= bitsCombined << 24 - nBytes % 4 * 8;
            nBytes += 1;
          }
        }
        return WordArray.create(words, nBytes);
      });

      /**
       * Base64 encoding strategy.
       */
      var Base64 = exports('Base64', {
        /**
         * Converts a word array to a Base64 string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The Base64 string.
         *
         * @static
         *
         * @example
         *
         *     const base64String = CryptoJS.enc.Base64.stringify(wordArray);
         */
        stringify: function stringify(wordArray) {
          // Shortcuts
          var words = wordArray.words,
            sigBytes = wordArray.sigBytes;
          var map = this._map;

          // Clamp excess bits
          wordArray.clamp();

          // Convert
          var base64Chars = [];
          for (var i = 0; i < sigBytes; i += 3) {
            var byte1 = words[i >>> 2] >>> 24 - i % 4 * 8 & 0xff;
            var byte2 = words[i + 1 >>> 2] >>> 24 - (i + 1) % 4 * 8 & 0xff;
            var byte3 = words[i + 2 >>> 2] >>> 24 - (i + 2) % 4 * 8 & 0xff;
            var triplet = byte1 << 16 | byte2 << 8 | byte3;
            for (var j = 0; j < 4 && i + j * 0.75 < sigBytes; j += 1) {
              base64Chars.push(map.charAt(triplet >>> 6 * (3 - j) & 0x3f));
            }
          }

          // Add padding
          var paddingChar = map.charAt(64);
          if (paddingChar) {
            while (base64Chars.length % 4) {
              base64Chars.push(paddingChar);
            }
          }
          return base64Chars.join('');
        },
        /**
         * Converts a Base64 string to a word array.
         *
         * @param {string} base64Str The Base64 string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     const wordArray = CryptoJS.enc.Base64.parse(base64String);
         */
        parse: function parse(base64Str) {
          // Shortcuts
          var base64StrLength = base64Str.length;
          var map = this._map;
          var reverseMap = this._reverseMap;
          if (!reverseMap) {
            this._reverseMap = [];
            reverseMap = this._reverseMap;
            for (var j = 0; j < map.length; j += 1) {
              reverseMap[map.charCodeAt(j)] = j;
            }
          }

          // Ignore padding
          var paddingChar = map.charAt(64);
          if (paddingChar) {
            var paddingIndex = base64Str.indexOf(paddingChar);
            if (paddingIndex !== -1) {
              base64StrLength = paddingIndex;
            }
          }

          // Convert
          return parseLoop(base64Str, base64StrLength, reverseMap);
        },
        _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Enemy.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './Tile.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, CCBoolean, Tile;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      CCBoolean = module.CCBoolean;
    }, function (module) {
      Tile = module.Tile;
    }],
    execute: function () {
      var _dec, _dec2, _class, _class2, _descriptor;
      cclegacy._RF.push({}, "2d857ounOJBTYoSju/2es+7", "Enemy", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var Enemy = exports('Enemy', (_dec = ccclass('Enemy'), _dec2 = property(CCBoolean), _dec(_class = (_class2 = /*#__PURE__*/function (_Tile) {
        _inheritsLoose(Enemy, _Tile);
        function Enemy() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Tile.call.apply(_Tile, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "canTouch", _descriptor, _assertThisInitialized(_this));
          return _this;
        }
        var _proto = Enemy.prototype;
        _proto.start = function start() {};
        _proto.update = function update(deltaTime) {};
        return Enemy;
      }(Tile), _descriptor = _applyDecoratedDescriptor(_class2.prototype, "canTouch", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return true;
        }
      }), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Enemy400.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './Enemy.ts', './MapManager.ts', './GlobalData.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, _createForOfIteratorHelperLoose, cclegacy, _decorator, Animation, CCFloat, Vec2, randomRange, randomRangeInt, Enemy, MapManager, TileType;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
      _createForOfIteratorHelperLoose = module.createForOfIteratorHelperLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Animation = module.Animation;
      CCFloat = module.CCFloat;
      Vec2 = module.Vec2;
      randomRange = module.randomRange;
      randomRangeInt = module.randomRangeInt;
    }, function (module) {
      Enemy = module.Enemy;
    }, function (module) {
      MapManager = module.MapManager;
    }, function (module) {
      TileType = module.TileType;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _class, _class2, _descriptor, _descriptor2;
      cclegacy._RF.push({}, "a1395CTnxdPvbS6gD8rjbDL", "Enemy400", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var Enemy400 = exports('Enemy400', (_dec = ccclass('Enemy400'), _dec2 = property(Animation), _dec3 = property(CCFloat), _dec(_class = (_class2 = /*#__PURE__*/function (_Enemy) {
        _inheritsLoose(Enemy400, _Enemy);
        function Enemy400() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Enemy.call.apply(_Enemy, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "animation", _descriptor, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "speed", _descriptor2, _assertThisInitialized(_this));
          _this.dir = new Vec2();
          return _this;
        }
        var _proto = Enemy400.prototype;
        _proto.start = function start() {
          this.findNewDirect();
        };
        _proto.flameHit = function flameHit(flame) {
          if (this.isDead) return;
          this.isDead = true;
          this.playAnimation("enemy400_die");
        };
        _proto.deadEnd = function deadEnd() {
          this.destroySelf();
        };
        _proto.playAnimation = function playAnimation(animationName) {
          var state = this.animation.getState(animationName);
          if (!state.isPlaying) {
            this.animation.play(animationName);
          }
        };
        _proto.findNewDirect = function findNewDirect() {
          var directs = [-1, 1];
          var rand = randomRange(0, 1);
          if (rand < 0.5) {
            this.dir.x = directs[randomRangeInt(0, 2)];
            this.dir.y = 0;
          } else {
            this.dir.x = 0;
            this.dir.y = directs[randomRangeInt(0, 2)];
          }
        };
        _proto.move = function move() {
          if (this.isDead) return;
          this.prePos.set(this.node.x, this.node.y);
          this.node.x += this.dir.x * this.speed;
          this.node.y += this.dir.y * this.speed;
          if (this.dir.x == 1) {
            this.playAnimation("enemy400_right");
            this.checkMoveRight();
          } else if (this.dir.x == -1) {
            this.playAnimation("enemy400_left");
            this.checkMoveLeft();
          } else if (this.dir.y == 1) {
            this.playAnimation("enemy400_up");
            this.checkMoveUp();
          } else if (this.dir.y == -1) {
            this.playAnimation("enemy400_down");
            this.checkMoveDown();
          }
          this.updateMapPos();
        };
        _proto.checkMoveRight = function checkMoveRight() {
          if (this.dir.x != 1) {
            return;
          }
          var rightDown = MapManager.instance.getTiles(this.minRow, this.maxCol);
          var rightUp = MapManager.instance.getTiles(this.maxRow, this.maxCol);
          var tiles = rightDown.concat(rightUp);
          for (var _iterator = _createForOfIteratorHelperLoose(tiles), _step; !(_step = _iterator()).done;) {
            var tile = _step.value;
            if (tile == this) {
              continue;
            }
            if (tile.type == TileType.PLAYER) ;else {
              if (tile.collideRect.intersects(this.collideRect)) {
                //如果发生相交就改变路径
                this.node.x = this.prePos.x;
                this.node.y = this.prePos.y;
                this.findNewDirect();
              }
            }
          }
        };
        _proto.checkMoveLeft = function checkMoveLeft() {
          if (this.dir.x != -1) {
            return;
          }
          var leftDown = MapManager.instance.getTiles(this.minRow, this.minCol);
          var leftUp = MapManager.instance.getTiles(this.maxRow, this.minCol);
          var tiles = leftDown.concat(leftUp);
          for (var _iterator2 = _createForOfIteratorHelperLoose(tiles), _step2; !(_step2 = _iterator2()).done;) {
            var tile = _step2.value;
            if (tile == this) {
              continue;
            }
            if (tile.type == TileType.PLAYER) ;else {
              if (tile.collideRect.intersects(this.collideRect)) {
                //如果发生相交就改变路径
                this.node.x = this.prePos.x;
                this.node.y = this.prePos.y;
                this.findNewDirect();
              }
            }
          }
        };
        _proto.checkMoveUp = function checkMoveUp() {
          if (this.dir.y != 1) {
            return;
          }
          var upLeft = MapManager.instance.getTiles(this.maxRow, this.minCol);
          var upRight = MapManager.instance.getTiles(this.maxRow, this.maxCol);
          var tiles = upLeft.concat(upRight);
          for (var _iterator3 = _createForOfIteratorHelperLoose(tiles), _step3; !(_step3 = _iterator3()).done;) {
            var tile = _step3.value;
            if (tile == this) {
              continue;
            }
            if (tile.type == TileType.PLAYER) ;else {
              if (tile.collideRect.intersects(this.collideRect)) {
                //如果发生相交就改变路径
                this.node.x = this.prePos.x;
                this.node.y = this.prePos.y;
                this.findNewDirect();
              }
            }
          }
        };
        _proto.checkMoveDown = function checkMoveDown() {
          if (this.dir.y != -1) {
            return;
          }
          var downLeft = MapManager.instance.getTiles(this.minRow, this.minCol);
          var downRight = MapManager.instance.getTiles(this.minRow, this.maxCol);
          var tiles = downLeft.concat(downRight);
          for (var _iterator4 = _createForOfIteratorHelperLoose(tiles), _step4; !(_step4 = _iterator4()).done;) {
            var tile = _step4.value;
            if (tile == this) {
              continue;
            }
            if (tile.type == TileType.PLAYER) ;else {
              if (tile.collideRect.intersects(this.collideRect)) {
                //如果发生相交就改变路径
                this.node.x = this.prePos.x;
                this.node.y = this.prePos.y;
                this.findNewDirect();
              }
            }
          }
        };
        _proto.update = function update(deltaTime) {
          this.move();
        };
        return Enemy400;
      }(Enemy), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "animation", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "speed", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return 2;
        }
      })), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Enemy401.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './Enemy.ts', './GlobalData.ts', './MapManager.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, _createForOfIteratorHelperLoose, cclegacy, _decorator, sp, CCFloat, Vec2, randomRangeInt, randomRange, Enemy, TileType, MapManager;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
      _createForOfIteratorHelperLoose = module.createForOfIteratorHelperLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      sp = module.sp;
      CCFloat = module.CCFloat;
      Vec2 = module.Vec2;
      randomRangeInt = module.randomRangeInt;
      randomRange = module.randomRange;
    }, function (module) {
      Enemy = module.Enemy;
    }, function (module) {
      TileType = module.TileType;
    }, function (module) {
      MapManager = module.MapManager;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _class, _class2, _descriptor, _descriptor2;
      cclegacy._RF.push({}, "f8b28+fv9xPy7vCFflytKbA", "Enemy401", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var Enemy401 = exports('Enemy401', (_dec = ccclass('Enemy401'), _dec2 = property(sp.Skeleton), _dec3 = property(CCFloat), _dec(_class = (_class2 = /*#__PURE__*/function (_Enemy) {
        _inheritsLoose(Enemy401, _Enemy);
        function Enemy401() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Enemy.call.apply(_Enemy, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "skeleton", _descriptor, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "speed", _descriptor2, _assertThisInitialized(_this));
          _this.dir = new Vec2();
          _this.skins = ["mob_mouse_01", "mob_mouse_02"];
          return _this;
        }
        var _proto = Enemy401.prototype;
        _proto.start = function start() {
          this.findNewDirect();
          this.skeleton.setSkin(this.skins[randomRangeInt(0, 2)]);
        };
        _proto.flameHit = function flameHit(flame) {
          if (this.isDead) return;
          this.isDead = true;
          this.playAnimation("die");
        };
        _proto.deadEnd = function deadEnd() {
          this.destroySelf();
        };
        _proto.playAnimation = function playAnimation(animationName, loop) {
          if (loop === void 0) {
            loop = true;
          }
          var track = this.skeleton.getCurrent(0);
          if (track.animation.name != animationName) {
            this.skeleton.setAnimation(0, animationName, loop);
          }
        };
        _proto.findNewDirect = function findNewDirect() {
          var directs = [-1, 1];
          var rand = randomRange(0, 1);
          if (rand < 0.5) {
            this.dir.x = directs[randomRangeInt(0, 2)];
            this.dir.y = 0;
          } else {
            this.dir.x = 0;
            this.dir.y = directs[randomRangeInt(0, 2)];
          }
        };
        _proto.move = function move() {
          if (this.isDead) return;
          this.prePos.set(this.node.x, this.node.y);
          this.node.x += this.dir.x * this.speed;
          this.node.y += this.dir.y * this.speed;
          if (this.dir.x == 1) {
            this.playAnimation("r_run");
            this.checkMoveRight();
          } else if (this.dir.x == -1) {
            this.playAnimation("l_run");
            this.checkMoveLeft();
          } else if (this.dir.y == 1) {
            this.playAnimation("b_run");
            this.checkMoveUp();
          } else if (this.dir.y == -1) {
            this.playAnimation("f_run");
            this.checkMoveDown();
          }
          this.updateMapPos();
        };
        _proto.checkMoveRight = function checkMoveRight() {
          if (this.dir.x != 1) {
            return;
          }
          var rightDown = MapManager.instance.getTiles(this.minRow, this.maxCol);
          var rightUp = MapManager.instance.getTiles(this.maxRow, this.maxCol);
          var tiles = rightDown.concat(rightUp);
          for (var _iterator = _createForOfIteratorHelperLoose(tiles), _step; !(_step = _iterator()).done;) {
            var tile = _step.value;
            if (tile == this) {
              continue;
            }
            if (tile.type == TileType.PLAYER) ;else {
              if (tile.collideRect.intersects(this.collideRect)) {
                //如果发生相交就改变路径
                this.node.x = this.prePos.x;
                this.node.y = this.prePos.y;
                this.findNewDirect();
              }
            }
          }
        };
        _proto.checkMoveLeft = function checkMoveLeft() {
          if (this.dir.x != -1) {
            return;
          }
          var leftDown = MapManager.instance.getTiles(this.minRow, this.minCol);
          var leftUp = MapManager.instance.getTiles(this.maxRow, this.minCol);
          var tiles = leftDown.concat(leftUp);
          for (var _iterator2 = _createForOfIteratorHelperLoose(tiles), _step2; !(_step2 = _iterator2()).done;) {
            var tile = _step2.value;
            if (tile == this) {
              continue;
            }
            if (tile.type == TileType.PLAYER) ;else {
              if (tile.collideRect.intersects(this.collideRect)) {
                //如果发生相交就改变路径
                this.node.x = this.prePos.x;
                this.node.y = this.prePos.y;
                this.findNewDirect();
              }
            }
          }
        };
        _proto.checkMoveUp = function checkMoveUp() {
          if (this.dir.y != 1) {
            return;
          }
          var upLeft = MapManager.instance.getTiles(this.maxRow, this.minCol);
          var upRight = MapManager.instance.getTiles(this.maxRow, this.maxCol);
          var tiles = upLeft.concat(upRight);
          for (var _iterator3 = _createForOfIteratorHelperLoose(tiles), _step3; !(_step3 = _iterator3()).done;) {
            var tile = _step3.value;
            if (tile == this) {
              continue;
            }
            if (tile.type == TileType.PLAYER) ;else {
              if (tile.collideRect.intersects(this.collideRect)) {
                //如果发生相交就改变路径
                this.node.x = this.prePos.x;
                this.node.y = this.prePos.y;
                this.findNewDirect();
              }
            }
          }
        };
        _proto.checkMoveDown = function checkMoveDown() {
          if (this.dir.y != -1) {
            return;
          }
          var downLeft = MapManager.instance.getTiles(this.minRow, this.minCol);
          var downRight = MapManager.instance.getTiles(this.minRow, this.maxCol);
          var tiles = downLeft.concat(downRight);
          for (var _iterator4 = _createForOfIteratorHelperLoose(tiles), _step4; !(_step4 = _iterator4()).done;) {
            var tile = _step4.value;
            if (tile == this) {
              continue;
            }
            if (tile.type == TileType.PLAYER) ;else {
              if (tile.collideRect.intersects(this.collideRect)) {
                //如果发生相交就改变路径
                this.node.x = this.prePos.x;
                this.node.y = this.prePos.y;
                this.findNewDirect();
              }
            }
          }
        };
        _proto.update = function update(deltaTime) {
          this.move();
        };
        return Enemy401;
      }(Enemy), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "skeleton", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "speed", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return 2;
        }
      })), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Entity.ts", ['cc', './GlobalData.ts'], function (exports) {
  var cclegacy, GlobalData;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      GlobalData = module.GlobalData;
    }],
    execute: function () {
      cclegacy._RF.push({}, "e83d7DIdnZFB7VvhpnTJL+x", "Entity", undefined);
      var Entity = exports('Entity', function Entity() {
        this.id = void 0;
        this.id = GlobalData.ENTITY_ID++;
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/EventManager.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc'], function (exports) {
  var _createClass, cclegacy, EventTarget;
  return {
    setters: [function (module) {
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
      EventTarget = module.EventTarget;
    }],
    execute: function () {
      cclegacy._RF.push({}, "b8b36tONbNM1Lh/NbjvswQB", "EventManager", undefined);
      var EventManager = exports('EventManager', /*#__PURE__*/function () {
        function EventManager() {
          this.on = void 0;
          this.off = void 0;
          this.emit = void 0;
          this._event = void 0;
          this._event = new EventTarget();
          this.on = this._event.on.bind(this._event);
          this.off = this._event.off.bind(this._event);
          this.emit = this._event.emit.bind(this._event);
        }
        _createClass(EventManager, null, [{
          key: "instance",
          get: function get() {
            if (!this._instance) {
              this._instance = new EventManager();
            }
            return this._instance;
          }
        }]);
        return EventManager;
      }());
      EventManager._instance = null;
      EventManager.ITEM_ICON_CLICK = "ITEM_ICON_CLICK";
      EventManager.LEVEL_LOADED = "LEVEL_LOADED";
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/evpkdf.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './core.ts', './md5.ts'], function (exports) {
  var _inheritsLoose, cclegacy, WordArray, Base, MD5Algo;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      WordArray = module.WordArray;
      Base = module.Base;
    }, function (module) {
      MD5Algo = module.MD5Algo;
    }],
    execute: function () {
      cclegacy._RF.push({}, "52e7aicKoJALby8zjg5MuXo", "evpkdf", undefined);

      /**
       * This key derivation function is meant to conform with EVP_BytesToKey.
       * www.openssl.org/docs/crypto/EVP_BytesToKey.html
       */
      var EvpKDFAlgo = exports('EvpKDFAlgo', /*#__PURE__*/function (_Base) {
        _inheritsLoose(EvpKDFAlgo, _Base);
        /**
         * Initializes a newly created key derivation function.
         *
         * @param {Object} cfg (Optional) The configuration options to use for the derivation.
         *
         * @example
         *
         *     const kdf = CryptoJS.algo.EvpKDF.create();
         *     const kdf = CryptoJS.algo.EvpKDF.create({ keySize: 8 });
         *     const kdf = CryptoJS.algo.EvpKDF.create({ keySize: 8, iterations: 1000 });
         */
        function EvpKDFAlgo(cfg) {
          var _this;
          _this = _Base.call(this) || this;

          /**
           * Configuration options.
           *
           * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
           * @property {Hasher} hasher The hash algorithm to use. Default: MD5
           * @property {number} iterations The number of iterations to perform. Default: 1
           */
          _this.cfg = Object.assign(new Base(), {
            keySize: 128 / 32,
            hasher: MD5Algo,
            iterations: 1
          }, cfg);
          return _this;
        }

        /**
         * Derives a key from a password.
         *
         * @param {WordArray|string} password The password.
         * @param {WordArray|string} salt A salt.
         *
         * @return {WordArray} The derived key.
         *
         * @example
         *
         *     const key = kdf.compute(password, salt);
         */
        var _proto = EvpKDFAlgo.prototype;
        _proto.compute = function compute(password, salt) {
          var block;

          // Shortcut
          var cfg = this.cfg;

          // Init hasher
          var hasher = cfg.hasher.create();

          // Initial values
          var derivedKey = WordArray.create();

          // Shortcuts
          var derivedKeyWords = derivedKey.words;
          var keySize = cfg.keySize,
            iterations = cfg.iterations;

          // Generate key
          while (derivedKeyWords.length < keySize) {
            if (block) {
              hasher.update(block);
            }
            block = hasher.update(password).finalize(salt);
            hasher.reset();

            // Iterations
            for (var i = 1; i < iterations; i += 1) {
              block = hasher.finalize(block);
              hasher.reset();
            }
            derivedKey.concat(block);
          }
          derivedKey.sigBytes = keySize * 4;
          return derivedKey;
        };
        return EvpKDFAlgo;
      }(Base));

      /**
       * Derives a key from a password.
       *
       * @param {WordArray|string} password The password.
       * @param {WordArray|string} salt A salt.
       * @param {Object} cfg (Optional) The configuration options to use for this computation.
       *
       * @return {WordArray} The derived key.
       *
       * @static
       *
       * @example
       *
       *     var key = CryptoJS.EvpKDF(password, salt);
       *     var key = CryptoJS.EvpKDF(password, salt, { keySize: 8 });
       *     var key = CryptoJS.EvpKDF(password, salt, { keySize: 8, iterations: 1000 });
       */
      var EvpKDF = exports('EvpKDF', function EvpKDF(password, salt, cfg) {
        return EvpKDFAlgo.create(cfg).compute(password, salt);
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Flame.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './Tile.ts'], function (exports) {
  var _inheritsLoose, cclegacy, _decorator, Tile;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
    }, function (module) {
      Tile = module.Tile;
    }],
    execute: function () {
      var _dec, _class;
      cclegacy._RF.push({}, "cd00ap9sRhCTqV/MHTd/LQP", "Flame", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var Flame = exports('Flame', (_dec = ccclass('Flame'), _dec(_class = /*#__PURE__*/function (_Tile) {
        _inheritsLoose(Flame, _Tile);
        function Flame() {
          return _Tile.apply(this, arguments) || this;
        }
        var _proto = Flame.prototype;
        _proto.start = function start() {};
        _proto.create = function create(bomb) {};
        _proto.update = function update(deltaTime) {};
        return Flame;
      }(Tile)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Flame300Center.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './Flame.ts', './MapManager.ts', './GlobalData.ts', './Resolver.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, Animation, Flame, MapManager, GlobalData, Resolver;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Animation = module.Animation;
    }, function (module) {
      Flame = module.Flame;
    }, function (module) {
      MapManager = module.MapManager;
    }, function (module) {
      GlobalData = module.GlobalData;
    }, function (module) {
      Resolver = module.Resolver;
    }],
    execute: function () {
      var _dec, _dec2, _class, _class2, _descriptor;
      cclegacy._RF.push({}, "ed38emm6A9NfI9cNW/WzL23", "Flame300Center", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var Flame300Center = exports('Flame300Center', (_dec = ccclass('Flame300Center'), _dec2 = property(Animation), _dec(_class = (_class2 = /*#__PURE__*/function (_Flame) {
        _inheritsLoose(Flame300Center, _Flame);
        function Flame300Center() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Flame.call.apply(_Flame, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "animation", _descriptor, _assertThisInitialized(_this));
          return _this;
        }
        var _proto = Flame300Center.prototype;
        _proto.start = function start() {};
        _proto.create = function create(bomb) {
          var _this2 = this;
          var row = bomb.minRow;
          var col = bomb.minCol;
          MapManager.instance.underMapNode.addChild(this.node);
          this.node.setPosition(col * GlobalData.TILE_WIDTH, row * GlobalData.TILE_HEIGHT);
          this.addToMap();
          this.scheduleOnce(function () {
            _this2.destroySelf();
          }, 0.5);
          var tiles = MapManager.instance.getTiles(row, col);
          tiles.forEach(function (tile) {
            if (tile == _this2) {
              return;
            }
            if (tile == bomb) {
              return;
            }
            Resolver.instance.resolve(_this2, tile);
          });
        };
        _proto.update = function update(deltaTime) {};
        return Flame300Center;
      }(Flame), _descriptor = _applyDecoratedDescriptor(_class2.prototype, "animation", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Flame300Connect.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './Flame.ts', './MapManager.ts', './Resolver.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, Animation, Node, Vec2, Flame, MapManager, Resolver;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Animation = module.Animation;
      Node = module.Node;
      Vec2 = module.Vec2;
    }, function (module) {
      Flame = module.Flame;
    }, function (module) {
      MapManager = module.MapManager;
    }, function (module) {
      Resolver = module.Resolver;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _class, _class2, _descriptor, _descriptor2;
      cclegacy._RF.push({}, "ee8a08dS49H4JCTgIN0yt7S", "Flame300Connect", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var Flame300Connect = exports('Flame300Connect', (_dec = ccclass('Flame300Connect'), _dec2 = property(Animation), _dec3 = property(Node), _dec(_class = (_class2 = /*#__PURE__*/function (_Flame) {
        _inheritsLoose(Flame300Connect, _Flame);
        function Flame300Connect() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Flame.call.apply(_Flame, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "animation", _descriptor, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "face", _descriptor2, _assertThisInitialized(_this));
          _this.bomb = null;
          _this.dir = new Vec2();
          return _this;
        }
        var _proto = Flame300Connect.prototype;
        _proto.start = function start() {
          var _this2 = this;
          if (this.dir.x == 1) {
            this.face.angle = -180;
          } else if (this.dir.y == 1) {
            this.face.angle = -90;
          } else if (this.dir.y == -1) {
            this.face.angle = 90;
          }
          this.scheduleOnce(function () {
            _this2.destroySelf();
          }, 0.5);
          var tiles = MapManager.instance.getTiles(this.minRow, this.minCol);
          tiles.forEach(function (tile) {
            if (tile == _this2) {
              return;
            }
            if (tile == _this2.bomb) {
              return;
            }
            Resolver.instance.resolve(_this2, tile);
          });
        };
        _proto.update = function update(deltaTime) {};
        return Flame300Connect;
      }(Flame), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "animation", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "face", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      })), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Flame300Creator.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './Flame300Center.ts', './ResourceManager.ts', './MapManager.ts', './Flame300Connect.ts', './GlobalData.ts'], function (exports) {
  var _createForOfIteratorHelperLoose, _createClass, cclegacy, instantiate, Prefab, Flame300Center, ResourceManager, MapManager, Flame300Connect, GlobalData, TileType;
  return {
    setters: [function (module) {
      _createForOfIteratorHelperLoose = module.createForOfIteratorHelperLoose;
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
      instantiate = module.instantiate;
      Prefab = module.Prefab;
    }, function (module) {
      Flame300Center = module.Flame300Center;
    }, function (module) {
      ResourceManager = module.ResourceManager;
    }, function (module) {
      MapManager = module.MapManager;
    }, function (module) {
      Flame300Connect = module.Flame300Connect;
    }, function (module) {
      GlobalData = module.GlobalData;
      TileType = module.TileType;
    }],
    execute: function () {
      cclegacy._RF.push({}, "e8356jd5AxFz4SQ5h5e3ij+", "Flame300Creator", undefined);
      var Flame300Creator = exports('Flame300Creator', /*#__PURE__*/function () {
        function Flame300Creator() {
          this.CenterPrefab = null;
          this.ConnectPrefab = null;
          this.blockFlameTypes = [TileType.STATIC, TileType.BOMB, TileType.PLAYER, TileType.MOVE];
          this.power = 3;
          this.CenterPrefab = ResourceManager.instance.getAsset("others/flames/300/300Center", "ab_prefabs", Prefab);
          this.ConnectPrefab = ResourceManager.instance.getAsset("others/flames/300/300Connect", "ab_prefabs", Prefab);
        }
        var _proto = Flame300Creator.prototype;
        //TODO::这里可以用对象池技术
        _proto.create = function create(bomb) {
          var row = bomb.minRow;
          var col = bomb.minCol;
          var center = instantiate(this.CenterPrefab).getComponent(Flame300Center);
          center.create(bomb);
          this.connectUp(row, col, bomb);
          this.connectDown(row, col, bomb);
          this.connectLeft(row, col, bomb);
          this.connectRight(row, col, bomb);
        };
        _proto.connectUp = function connectUp(row, col, bomb) {
          var isEnd = false;
          for (var i = 0; i < this.power; i++) {
            var curtRow = row + i + 1;
            var curtCol = col;
            var tiles = MapManager.instance.getTiles(curtRow, curtCol);
            isEnd = this.blockToSlide(tiles, this.blockFlameTypes);
            var up = instantiate(this.ConnectPrefab).getComponent(Flame300Connect);
            up.dir.y = 1;
            up.bomb = bomb;
            up.node.setPosition(curtCol * GlobalData.TILE_WIDTH, curtRow * GlobalData.TILE_HEIGHT);
            MapManager.instance.underMapNode.addChild(up.node);
            up.addToMap();
            if (isEnd) {
              return;
            }
          }
        };
        _proto.connectDown = function connectDown(row, col, bomb) {
          var isEnd = false;
          for (var i = 0; i < this.power; i++) {
            var curtRow = row - i - 1;
            var curtCol = col;
            var tiles = MapManager.instance.getTiles(curtRow, curtCol);
            isEnd = this.blockToSlide(tiles, this.blockFlameTypes);
            var down = instantiate(this.ConnectPrefab).getComponent(Flame300Connect);
            down.dir.y = -1;
            down.bomb = bomb;
            down.node.setPosition(curtCol * GlobalData.TILE_WIDTH, curtRow * GlobalData.TILE_HEIGHT);
            MapManager.instance.underMapNode.addChild(down.node);
            down.addToMap();
            if (isEnd) {
              return;
            }
          }
        };
        _proto.connectLeft = function connectLeft(row, col, bomb) {
          var isEnd = false;
          for (var i = 0; i < this.power; i++) {
            var curtRow = row;
            var curtCol = col - i - 1;
            var tiles = MapManager.instance.getTiles(curtRow, curtCol);
            isEnd = this.blockToSlide(tiles, this.blockFlameTypes);
            var left = instantiate(this.ConnectPrefab).getComponent(Flame300Connect);
            left.dir.x = -1;
            left.bomb = bomb;
            left.node.setPosition(curtCol * GlobalData.TILE_WIDTH, curtRow * GlobalData.TILE_HEIGHT);
            MapManager.instance.underMapNode.addChild(left.node);
            left.addToMap();
            if (isEnd) {
              return;
            }
          }
        };
        _proto.connectRight = function connectRight(row, col, bomb) {
          var isEnd = false;
          for (var i = 0; i < this.power; i++) {
            var curtRow = row;
            var curtCol = col + i + 1;
            var tiles = MapManager.instance.getTiles(curtRow, curtCol);
            isEnd = this.blockToSlide(tiles, this.blockFlameTypes);
            var right = instantiate(this.ConnectPrefab).getComponent(Flame300Connect);
            right.dir.x = 1;
            right.bomb = bomb;
            right.node.setPosition(curtCol * GlobalData.TILE_WIDTH, curtRow * GlobalData.TILE_HEIGHT);
            MapManager.instance.underMapNode.addChild(right.node);
            right.addToMap();
            if (isEnd) {
              return;
            }
          }
        };
        _proto.blockToSlide = function blockToSlide(tiles, types) {
          for (var _iterator = _createForOfIteratorHelperLoose(types), _step; !(_step = _iterator()).done;) {
            var type = _step.value;
            if (MapManager.instance.hasType(tiles, type)) {
              return true;
            }
          }
          return false;
        };
        _createClass(Flame300Creator, null, [{
          key: "instance",
          get: function get() {
            if (!Flame300Creator._instance) {
              Flame300Creator._instance = new Flame300Creator();
            }
            return Flame300Creator._instance;
          }
        }]);
        return Flame300Creator;
      }());
      Flame300Creator._instance = null;
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/FlameCreator.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './Flame300Creator.ts'], function (exports) {
  var _createClass, cclegacy, Flame300Creator;
  return {
    setters: [function (module) {
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      Flame300Creator = module.Flame300Creator;
    }],
    execute: function () {
      cclegacy._RF.push({}, "0f270t1ul9Gkq9zJdkf4W5Q", "FlameCreator", undefined);
      var FlameCreator = exports('FlameCreator', /*#__PURE__*/function () {
        function FlameCreator() {}
        var _proto = FlameCreator.prototype;
        _proto.create = function create(bomb) {
          if (bomb.flameId == 300) {
            Flame300Creator.instance.create(bomb);
          }
        };
        _createClass(FlameCreator, null, [{
          key: "instance",
          get: function get() {
            if (!FlameCreator._instance) {
              FlameCreator._instance = new FlameCreator();
            }
            return FlameCreator._instance;
          }
        }]);
        return FlameCreator;
      }());
      FlameCreator._instance = null;
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/GlobalData.ts", ['cc'], function (exports) {
  var cclegacy, Enum;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
      Enum = module.Enum;
    }],
    execute: function () {
      cclegacy._RF.push({}, "844ffm3MO9NzZ8EnMtefWMU", "GlobalData", undefined);
      var BundleType = exports('BundleType', {
        Asset: "Asset",
        Scence: "Scence"
      });
      var PlayerSlotType = exports('PlayerSlotType', /*#__PURE__*/function (PlayerSlotType) {
        PlayerSlotType[PlayerSlotType["CAP"] = 1] = "CAP";
        PlayerSlotType[PlayerSlotType["COAT"] = 2] = "COAT";
        return PlayerSlotType;
      }({}));
      var TileType = exports('TileType', /*#__PURE__*/function (TileType) {
        TileType[TileType["EMPTY"] = 0] = "EMPTY";
        TileType[TileType["STATIC"] = 1] = "STATIC";
        TileType[TileType["MOVE"] = 2] = "MOVE";
        TileType[TileType["PLAYER"] = 3] = "PLAYER";
        TileType[TileType["ITEM"] = 4] = "ITEM";
        TileType[TileType["BOMB"] = 5] = "BOMB";
        TileType[TileType["FLAME"] = 6] = "FLAME";
        TileType[TileType["ENEMY"] = 7] = "ENEMY";
        return TileType;
      }({}));
      Enum(TileType);
      var PlayerCollideFeedBack = exports('PlayerCollideFeedBack', /*#__PURE__*/function (PlayerCollideFeedBack) {
        PlayerCollideFeedBack[PlayerCollideFeedBack["NONE"] = 0] = "NONE";
        PlayerCollideFeedBack[PlayerCollideFeedBack["SLIDE"] = 1] = "SLIDE";
        PlayerCollideFeedBack[PlayerCollideFeedBack["STOP"] = 2] = "STOP";
        return PlayerCollideFeedBack;
      }({}));
      Enum(PlayerCollideFeedBack);
      var GlobalData = exports('GlobalData', function GlobalData() {});
      GlobalData.VERSION = "1.0.0";
      GlobalData.ENTITY_ID = 0;
      GlobalData.TILE_WIDTH = 48;
      GlobalData.TILE_HEIGHT = 48;
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/InputMapping.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc'], function (exports) {
  var _createClass, cclegacy, KeyCode;
  return {
    setters: [function (module) {
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
      KeyCode = module.KeyCode;
    }],
    execute: function () {
      cclegacy._RF.push({}, "9762dkSIeJIHbs7ZoPrETNs", "InputMapping", undefined);

      //对应游戏里面的按键，最好不要起具体的名字比如：fire,因为角色对应的按键功能可能不一样
      var INPUT_KEYS = exports('INPUT_KEYS', /*#__PURE__*/function (INPUT_KEYS) {
        INPUT_KEYS[INPUT_KEYS["UI_UP"] = 1] = "UI_UP";
        INPUT_KEYS[INPUT_KEYS["UI_DOWN"] = 2] = "UI_DOWN";
        INPUT_KEYS[INPUT_KEYS["UI_LEFT"] = 3] = "UI_LEFT";
        INPUT_KEYS[INPUT_KEYS["UI_RIGHT"] = 4] = "UI_RIGHT";
        INPUT_KEYS[INPUT_KEYS["UI_A"] = 5] = "UI_A";
        INPUT_KEYS[INPUT_KEYS["UI_B"] = 6] = "UI_B";
        INPUT_KEYS[INPUT_KEYS["UI_C"] = 7] = "UI_C";
        INPUT_KEYS[INPUT_KEYS["UI_D"] = 8] = "UI_D";
        INPUT_KEYS[INPUT_KEYS["UI_E"] = 9] = "UI_E";
        INPUT_KEYS[INPUT_KEYS["UI_F"] = 10] = "UI_F";
        INPUT_KEYS[INPUT_KEYS["UI_G"] = 11] = "UI_G";
        INPUT_KEYS[INPUT_KEYS["UI_H"] = 12] = "UI_H";
        return INPUT_KEYS;
      }({}));
      var InputMapping = exports('InputMapping', /*#__PURE__*/function () {
        function InputMapping() {
          this.keys = new Map();
          this.defaultMapping();
        }
        var _proto = InputMapping.prototype;
        _proto.defaultMapping = function defaultMapping() {
          this.addMapping(KeyCode.ARROW_UP, INPUT_KEYS.UI_UP);
          this.addMapping(KeyCode.ARROW_DOWN, INPUT_KEYS.UI_DOWN);
          this.addMapping(KeyCode.ARROW_LEFT, INPUT_KEYS.UI_LEFT);
          this.addMapping(KeyCode.ARROW_RIGHT, INPUT_KEYS.UI_RIGHT);
        };
        _proto.addMapping = function addMapping(key, inputKey) {
          this.keys.set(key, inputKey);
        };
        _proto.getInput = function getInput(key) {
          var inputKey = this.keys.get(key);
          return inputKey;
        };
        _createClass(InputMapping, null, [{
          key: "instance",
          get: function get() {
            if (!InputMapping._instance) {
              InputMapping._instance = new InputMapping();
            }
            return InputMapping._instance;
          }
        }]);
        return InputMapping;
      }());
      InputMapping._instance = null;
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/ItemIcon.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './ResourceManager.ts', './EventManager.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, _createClass, cclegacy, _decorator, Sprite, Label, NodeEventType, SpriteFrame, Component, ResourceManager, EventManager;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Sprite = module.Sprite;
      Label = module.Label;
      NodeEventType = module.NodeEventType;
      SpriteFrame = module.SpriteFrame;
      Component = module.Component;
    }, function (module) {
      ResourceManager = module.ResourceManager;
    }, function (module) {
      EventManager = module.EventManager;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _class, _class2, _descriptor, _descriptor2;
      cclegacy._RF.push({}, "87bc9to28FIOKLwoausi6Yp", "ItemIcon", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var ItemIcon = exports('ItemIcon', (_dec = ccclass('ItemIcon'), _dec2 = property(Sprite), _dec3 = property(Label), _dec(_class = (_class2 = /*#__PURE__*/function (_Component) {
        _inheritsLoose(ItemIcon, _Component);
        function ItemIcon() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Component.call.apply(_Component, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "icon", _descriptor, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "amount", _descriptor2, _assertThisInitialized(_this));
          _this.mItemId = 0;
          _this.mItemAmount = 0;
          return _this;
        }
        var _proto = ItemIcon.prototype;
        _proto.start = function start() {
          this.node.on(NodeEventType.TOUCH_END, this.onTouchEnd, this);
        };
        _proto.onTouchEnd = function onTouchEnd(event) {
          EventManager.instance.emit(EventManager.ITEM_ICON_CLICK, this.itemId);
        };
        _proto.clear = function clear() {
          this.icon.spriteFrame = null;
          this.mItemId = 0;
          this.itemAmount = 0;
        };
        _proto.loadIcon = function loadIcon() {
          var _this2 = this;
          var spriteFrame = ResourceManager.instance.getAsset("items/icons/" + this.itemId + "/spriteFrame", "ab_textures", SpriteFrame);
          if (spriteFrame) {
            this.icon.spriteFrame = spriteFrame;
          } else {
            ResourceManager.instance.directLoad("ab_textures", "items/icons/" + this.itemId + "/spriteFrame", false, SpriteFrame, function (err, spriteFrame) {
              if (err) {
                console.log(err);
              } else {
                _this2.icon.spriteFrame = spriteFrame;
              }
            });
          }
        };
        _proto.update = function update(deltaTime) {};
        _createClass(ItemIcon, [{
          key: "itemAmount",
          get: function get() {
            return this.mItemAmount;
          },
          set: function set(amount) {
            this.mItemAmount = amount;
            this.amount.string = amount.toString();
          }
        }, {
          key: "itemId",
          get: function get() {
            return this.mItemId;
          },
          set: function set(id) {
            if (this.mItemId != id) {
              this.mItemId = id;
              this.loadIcon();
            }
          }
        }]);
        return ItemIcon;
      }(Component), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "icon", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "amount", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      })), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Level.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './ResourceManager.ts', './GlobalData.ts', './MapManager.ts', './Tile.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, CCInteger, Node, JsonAsset, Prefab, instantiate, Component, ResourceManager, GlobalData, MapManager, Tile;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      CCInteger = module.CCInteger;
      Node = module.Node;
      JsonAsset = module.JsonAsset;
      Prefab = module.Prefab;
      instantiate = module.instantiate;
      Component = module.Component;
    }, function (module) {
      ResourceManager = module.ResourceManager;
    }, function (module) {
      GlobalData = module.GlobalData;
    }, function (module) {
      MapManager = module.MapManager;
    }, function (module) {
      Tile = module.Tile;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _dec4, _dec5, _class, _class2, _descriptor, _descriptor2, _descriptor3, _descriptor4;
      cclegacy._RF.push({}, "2331516rhtBMJDyB2I1UakC", "Level", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var Level = exports('Level', (_dec = ccclass('Level'), _dec2 = property({
        type: CCInteger
      }), _dec3 = property(Node), _dec4 = property(Node), _dec5 = property(Node), _dec(_class = (_class2 = /*#__PURE__*/function (_Component) {
        _inheritsLoose(Level, _Component);
        function Level() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Component.call.apply(_Component, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "mapId", _descriptor, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "mapNode", _descriptor2, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "underMapNode", _descriptor3, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "overMapNode", _descriptor4, _assertThisInitialized(_this));
          _this.mapData = null;
          return _this;
        }
        var _proto = Level.prototype;
        _proto.start = function start() {
          this.mapData = ResourceManager.instance.getAsset("maps/" + this.mapId, "ab_data", JsonAsset).json;
          this.createMap();
        };
        _proto.createMap = function createMap() {
          var map = this.mapData.map;
          MapManager.instance.initMap(this.mapData, this);
          for (var i = 0; i < map.length; i++) {
            var objectId = map[i];
            var col = i % this.mapData.cols;
            var row = this.mapData.rows - 1 - Math.floor(i / this.mapData.cols);
            if (objectId > 99 && objectId < 200) {
              //角色
              var PlayerPrefab = ResourceManager.instance.getAsset("others/players/" + objectId, "ab_prefabs", Prefab);
              var playerNode = instantiate(PlayerPrefab);
              //TODO::位置设置的不对，应该是碰撞区域的中心而不是图形区域的中心
              playerNode.setPosition(col * GlobalData.TILE_WIDTH, row * GlobalData.TILE_HEIGHT);
              this.mapNode.addChild(playerNode);
              var player = playerNode.getComponent(Tile);
              player.addToMap();
            } else if (objectId > 399 && objectId < 700) {
              //敌人
              var EnemyPrefab = ResourceManager.instance.getAsset("others/enemy/" + objectId, "ab_prefabs", Prefab);
              var enemyNode = instantiate(EnemyPrefab);
              enemyNode.setPosition(col * GlobalData.TILE_WIDTH, row * GlobalData.TILE_HEIGHT);
              this.mapNode.addChild(enemyNode);
              var enemy = enemyNode.getComponent(Tile);
              enemy.addToMap();
            } else if (objectId > 999 && objectId < 2000) {
              var TilePrefab = ResourceManager.instance.getAsset("tiles/" + objectId, "ab_prefabs", Prefab);
              var tileNode = instantiate(TilePrefab);
              tileNode.setPosition(col * GlobalData.TILE_WIDTH, row * GlobalData.TILE_HEIGHT);
              this.mapNode.addChild(tileNode);
              var tile = tileNode.getComponent(Tile);
              tile.addToMap();
            }
          }
        };
        _proto.createBomb = function createBomb() {};
        _proto.destroySelf = function destroySelf() {
          this.node.removeFromParent();
          this.destroy();
        };
        _proto.sortTiles = function sortTiles() {
          this.mapNode.children.sort(function (a, b) {
            return b.x - a.x;
          });
          this.mapNode.children.sort(function (a, b) {
            return b.y - a.y;
          });
          this.underMapNode.children.sort(function (a, b) {
            return b.y - a.y;
          });
          this.overMapNode.children.sort(function (a, b) {
            return b.y - a.y;
          });
        };
        _proto.update = function update(deltaTime) {
          this.sortTiles();
        };
        return Level;
      }(Component), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "mapId", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return 0;
        }
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "mapNode", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _descriptor3 = _applyDecoratedDescriptor(_class2.prototype, "underMapNode", [_dec4], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _descriptor4 = _applyDecoratedDescriptor(_class2.prototype, "overMapNode", [_dec5], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      })), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/LevelManager.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './ResourceManager.ts', './Level.ts', './EventManager.ts'], function (exports) {
  var _createClass, cclegacy, Prefab, instantiate, ResourceManager, Level, EventManager;
  return {
    setters: [function (module) {
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
      Prefab = module.Prefab;
      instantiate = module.instantiate;
    }, function (module) {
      ResourceManager = module.ResourceManager;
    }, function (module) {
      Level = module.Level;
    }, function (module) {
      EventManager = module.EventManager;
    }],
    execute: function () {
      cclegacy._RF.push({}, "bbe92b94HRLKqApgl+I+83J", "LevelManager", undefined);
      var LevelManager = exports('LevelManager', /*#__PURE__*/function () {
        function LevelManager() {
          this.levelId = 0;
          this.level = null;
        }
        var _proto = LevelManager.prototype;
        _proto.setLevel = function setLevel(aLevel) {
          if (this.level) {
            this.level.destroySelf();
          }
          this.level = aLevel;
        };
        _proto.loadLevel = function loadLevel() {
          var _this = this;
          var levelPrefab = ResourceManager.instance.getAsset("levels/" + this.levelId, "ab_prefabs", Prefab);
          if (levelPrefab) {
            var level = instantiate(levelPrefab).getComponent(Level);
            this.setLevel(level);
            EventManager.instance.emit(EventManager.LEVEL_LOADED);
          } else {
            ResourceManager.instance.directLoad("ab_prefabs", "levels/" + this.levelId, false, Prefab, function (err, prefab) {
              if (err) {
                console.log(err);
              } else {
                var _level = instantiate(prefab).getComponent(Level);
                _this.setLevel(_level);
                EventManager.instance.emit(EventManager.LEVEL_LOADED);
              }
            });
            // let batch = ResourceManager.instance.createNewBatch("LevelLoaded");
            // batch.addResource(`levels/${this.mapId}/${this.levelId}`, "ab_prefabs", BundleType.Asset, Prefab, EventManager.LEVEL_LOADED, EventManager.instance);
            // batch.start();
          }
        };

        _createClass(LevelManager, null, [{
          key: "instance",
          get: function get() {
            if (!LevelManager._instance) {
              LevelManager._instance = new LevelManager();
            }
            return LevelManager._instance;
          }
        }]);
        return LevelManager;
      }());
      LevelManager._instance = null;
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/main", ['./Test.ts', './Backpack.ts', './BackpackGrid.ts', './ConfigRole.ts', './Entity.ts', './InputMapping.ts', './ItemIcon.ts', './Level.ts', './LevelManager.ts', './MapManager.ts', './PlayerConfigPanel.ts', './PlayerSlot.ts', './Preload.ts', './TickManager.ts', './UserData.ts', './Bomb200.ts', './Bomb200Creator.ts', './StateBomb200Explode.ts', './StateBomb200Idle.ts', './Bomb.ts', './BombCreator.ts', './AudioManager.ts', './EventManager.ts', './GlobalData.ts', './ResourceManager.ts', './StateBase.ts', './StateMachine.ts', './StorageDataManager.ts', './Utils.ts', './aes.ts', './cipher-core.ts', './core.ts', './enc-base64.ts', './evpkdf.ts', './md5.ts', './CSVManager.ts', './CSVParser.ts', './PeerJS.ts', './Enemy400.ts', './Enemy401.ts', './Enemy.ts', './Flame300Center.ts', './Flame300Connect.ts', './Flame300Creator.ts', './Flame.ts', './FlameCreator.ts', './Player100.ts', './StatePlayer100Idle.ts', './StatePlayer100Move.ts', './Player101.ts', './StatePlayer101Idle.ts', './StatePlayer101Move.ts', './Player.ts', './ResolveBase.ts', './ResolveMoveBlock.ts', './ResolvePlayerBomb.ts', './ResolvePlayerStatic.ts', './Resolver.ts', './ResovleFlameTile.ts', './ResovlePlayerMove.ts', './MoveTile1002.ts', './MoveTile.ts', './StaticTile.ts', './Tile.ts'], function () {
  return {
    setters: [null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null],
    execute: function () {}
  };
});

System.register("chunks:///_virtual/MapManager.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './Tile.ts'], function (exports) {
  var _createClass, cclegacy, TileMapRef;
  return {
    setters: [function (module) {
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      TileMapRef = module.TileMapRef;
    }],
    execute: function () {
      cclegacy._RF.push({}, "39587X8HtNKErrCIwc0e6Qv", "MapManager", undefined);
      //TODO::可能需要单独的PlayerMananger，用来管理地图上的所有角色/BombManager/FlameManager 
      var MapManager = exports('MapManager', /*#__PURE__*/function () {
        function MapManager() {
          this.player = void 0;
          this.mapNode = void 0;
          this.underMapNode = void 0;
          this.overMapNode = void 0;
          this.map = void 0;
        }
        var _proto = MapManager.prototype;
        _proto.initMap = function initMap(data, level) {
          this.map = [];
          for (var r = 0; r < data.rows; r++) {
            this.map[r] = [];
            for (var c = 0; c < data.cols; c++) {
              this.map[r][c] = [];
            }
          }
          this.mapNode = level.mapNode;
          this.overMapNode = level.overMapNode;
          this.underMapNode = level.underMapNode;
        };
        _proto.isEmpty = function isEmpty(row, col) {
          return this.map[row][col].length == 0;
        };
        _proto.getTiles = function getTiles(row, col) {
          return this.map[row][col];
        };
        _proto.getType = function getType(tiles) {
          var tileTypes = [];
          for (var i = 0; i < tiles.length; i++) {
            tileTypes.push(tiles[i].type);
          }
          return tileTypes;
        };
        _proto.hasType = function hasType(tiles, type) {
          for (var i = 0; i < tiles.length; i++) {
            if (tiles[i].type == type) {
              return true;
            }
          }
          return false;
        };
        _proto.hasExcludeType = function hasExcludeType(tiles, tile, type) {
          for (var i = 0; i < tiles.length; i++) {
            if (tiles[i] == tile) {
              return false;
            }
            if (tiles[i].type == type) {
              return true;
            }
          }
          return false;
        };
        _proto.hasTile = function hasTile(tile, row, col, index) {
          if (index === void 0) {
            index = -1;
          }
          return this.map[row][col][index] == tile;
        };
        _proto.addTile = function addTile(tile, row, col) {
          if (this.map[row][col].includes(tile)) {
            return;
          }
          this.map[row][col].push(tile);
          tile.mapRefs.push(new TileMapRef(tile, row, col));
        };
        _proto.removeTile = function removeTile(tile, row, col) {
          var tiles = this.map[row][col];
          for (var i = 0; i < tiles.length; i++) {
            if (tiles[i] == tile) {
              tiles.splice(i, 1);
              break;
            }
          }
        }

        // createFlame(bomb:Bomb):void{
        //     let FlamePrefab = ResourceManager.instance.getAsset(`others/flames/${bomb.flameId}/${bomb.flameId}`, "ab_prefabs", Prefab) as Prefab;
        //     let flame = instantiate(FlamePrefab).getComponent(Flame);
        //     flame.create(bomb);
        // }
        ;

        _createClass(MapManager, null, [{
          key: "instance",
          get: function get() {
            if (!MapManager._instance) {
              MapManager._instance = new MapManager();
            }
            return MapManager._instance;
          }
        }]);
        return MapManager;
      }());
      MapManager._instance = null;
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/md5.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './core.ts'], function (exports) {
  var _inheritsLoose, cclegacy, WordArray, Hasher;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      WordArray = module.WordArray;
      Hasher = module.Hasher;
    }],
    execute: function () {
      cclegacy._RF.push({}, "047b4MULW1PI6wioUhcpTTe", "md5", undefined);

      // Constants table
      var T = [];

      // Compute constants
      for (var i = 0; i < 64; i += 1) {
        T[i] = Math.abs(Math.sin(i + 1)) * 0x100000000 | 0;
      }
      var FF = function FF(a, b, c, d, x, s, t) {
        var n = a + (b & c | ~b & d) + x + t;
        return (n << s | n >>> 32 - s) + b;
      };
      var GG = function GG(a, b, c, d, x, s, t) {
        var n = a + (b & d | c & ~d) + x + t;
        return (n << s | n >>> 32 - s) + b;
      };
      var HH = function HH(a, b, c, d, x, s, t) {
        var n = a + (b ^ c ^ d) + x + t;
        return (n << s | n >>> 32 - s) + b;
      };
      var II = function II(a, b, c, d, x, s, t) {
        var n = a + (c ^ (b | ~d)) + x + t;
        return (n << s | n >>> 32 - s) + b;
      };

      /**
       * MD5 hash algorithm.
       */
      var MD5Algo = exports('MD5Algo', /*#__PURE__*/function (_Hasher) {
        _inheritsLoose(MD5Algo, _Hasher);
        function MD5Algo() {
          return _Hasher.apply(this, arguments) || this;
        }
        var _proto = MD5Algo.prototype;
        _proto._doReset = function _doReset() {
          this._hash = new WordArray([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]);
        };
        _proto._doProcessBlock = function _doProcessBlock(M, offset) {
          var _M = M;

          // Swap endian
          for (var _i = 0; _i < 16; _i += 1) {
            // Shortcuts
            var offset_i = offset + _i;
            var M_offset_i = M[offset_i];
            _M[offset_i] = (M_offset_i << 8 | M_offset_i >>> 24) & 0x00ff00ff | (M_offset_i << 24 | M_offset_i >>> 8) & 0xff00ff00;
          }

          // Shortcuts
          var H = this._hash.words;
          var M_offset_0 = _M[offset + 0];
          var M_offset_1 = _M[offset + 1];
          var M_offset_2 = _M[offset + 2];
          var M_offset_3 = _M[offset + 3];
          var M_offset_4 = _M[offset + 4];
          var M_offset_5 = _M[offset + 5];
          var M_offset_6 = _M[offset + 6];
          var M_offset_7 = _M[offset + 7];
          var M_offset_8 = _M[offset + 8];
          var M_offset_9 = _M[offset + 9];
          var M_offset_10 = _M[offset + 10];
          var M_offset_11 = _M[offset + 11];
          var M_offset_12 = _M[offset + 12];
          var M_offset_13 = _M[offset + 13];
          var M_offset_14 = _M[offset + 14];
          var M_offset_15 = _M[offset + 15];

          // Working varialbes
          var a = H[0];
          var b = H[1];
          var c = H[2];
          var d = H[3];

          // Computation
          a = FF(a, b, c, d, M_offset_0, 7, T[0]);
          d = FF(d, a, b, c, M_offset_1, 12, T[1]);
          c = FF(c, d, a, b, M_offset_2, 17, T[2]);
          b = FF(b, c, d, a, M_offset_3, 22, T[3]);
          a = FF(a, b, c, d, M_offset_4, 7, T[4]);
          d = FF(d, a, b, c, M_offset_5, 12, T[5]);
          c = FF(c, d, a, b, M_offset_6, 17, T[6]);
          b = FF(b, c, d, a, M_offset_7, 22, T[7]);
          a = FF(a, b, c, d, M_offset_8, 7, T[8]);
          d = FF(d, a, b, c, M_offset_9, 12, T[9]);
          c = FF(c, d, a, b, M_offset_10, 17, T[10]);
          b = FF(b, c, d, a, M_offset_11, 22, T[11]);
          a = FF(a, b, c, d, M_offset_12, 7, T[12]);
          d = FF(d, a, b, c, M_offset_13, 12, T[13]);
          c = FF(c, d, a, b, M_offset_14, 17, T[14]);
          b = FF(b, c, d, a, M_offset_15, 22, T[15]);
          a = GG(a, b, c, d, M_offset_1, 5, T[16]);
          d = GG(d, a, b, c, M_offset_6, 9, T[17]);
          c = GG(c, d, a, b, M_offset_11, 14, T[18]);
          b = GG(b, c, d, a, M_offset_0, 20, T[19]);
          a = GG(a, b, c, d, M_offset_5, 5, T[20]);
          d = GG(d, a, b, c, M_offset_10, 9, T[21]);
          c = GG(c, d, a, b, M_offset_15, 14, T[22]);
          b = GG(b, c, d, a, M_offset_4, 20, T[23]);
          a = GG(a, b, c, d, M_offset_9, 5, T[24]);
          d = GG(d, a, b, c, M_offset_14, 9, T[25]);
          c = GG(c, d, a, b, M_offset_3, 14, T[26]);
          b = GG(b, c, d, a, M_offset_8, 20, T[27]);
          a = GG(a, b, c, d, M_offset_13, 5, T[28]);
          d = GG(d, a, b, c, M_offset_2, 9, T[29]);
          c = GG(c, d, a, b, M_offset_7, 14, T[30]);
          b = GG(b, c, d, a, M_offset_12, 20, T[31]);
          a = HH(a, b, c, d, M_offset_5, 4, T[32]);
          d = HH(d, a, b, c, M_offset_8, 11, T[33]);
          c = HH(c, d, a, b, M_offset_11, 16, T[34]);
          b = HH(b, c, d, a, M_offset_14, 23, T[35]);
          a = HH(a, b, c, d, M_offset_1, 4, T[36]);
          d = HH(d, a, b, c, M_offset_4, 11, T[37]);
          c = HH(c, d, a, b, M_offset_7, 16, T[38]);
          b = HH(b, c, d, a, M_offset_10, 23, T[39]);
          a = HH(a, b, c, d, M_offset_13, 4, T[40]);
          d = HH(d, a, b, c, M_offset_0, 11, T[41]);
          c = HH(c, d, a, b, M_offset_3, 16, T[42]);
          b = HH(b, c, d, a, M_offset_6, 23, T[43]);
          a = HH(a, b, c, d, M_offset_9, 4, T[44]);
          d = HH(d, a, b, c, M_offset_12, 11, T[45]);
          c = HH(c, d, a, b, M_offset_15, 16, T[46]);
          b = HH(b, c, d, a, M_offset_2, 23, T[47]);
          a = II(a, b, c, d, M_offset_0, 6, T[48]);
          d = II(d, a, b, c, M_offset_7, 10, T[49]);
          c = II(c, d, a, b, M_offset_14, 15, T[50]);
          b = II(b, c, d, a, M_offset_5, 21, T[51]);
          a = II(a, b, c, d, M_offset_12, 6, T[52]);
          d = II(d, a, b, c, M_offset_3, 10, T[53]);
          c = II(c, d, a, b, M_offset_10, 15, T[54]);
          b = II(b, c, d, a, M_offset_1, 21, T[55]);
          a = II(a, b, c, d, M_offset_8, 6, T[56]);
          d = II(d, a, b, c, M_offset_15, 10, T[57]);
          c = II(c, d, a, b, M_offset_6, 15, T[58]);
          b = II(b, c, d, a, M_offset_13, 21, T[59]);
          a = II(a, b, c, d, M_offset_4, 6, T[60]);
          d = II(d, a, b, c, M_offset_11, 10, T[61]);
          c = II(c, d, a, b, M_offset_2, 15, T[62]);
          b = II(b, c, d, a, M_offset_9, 21, T[63]);

          // Intermediate hash value
          H[0] = H[0] + a | 0;
          H[1] = H[1] + b | 0;
          H[2] = H[2] + c | 0;
          H[3] = H[3] + d | 0;
        }
        /* eslint-ensable no-param-reassign */;
        _proto._doFinalize = function _doFinalize() {
          // Shortcuts
          var data = this._data;
          var dataWords = data.words;
          var nBitsTotal = this._nDataBytes * 8;
          var nBitsLeft = data.sigBytes * 8;

          // Add padding
          dataWords[nBitsLeft >>> 5] |= 0x80 << 24 - nBitsLeft % 32;
          var nBitsTotalH = Math.floor(nBitsTotal / 0x100000000);
          var nBitsTotalL = nBitsTotal;
          dataWords[(nBitsLeft + 64 >>> 9 << 4) + 15] = (nBitsTotalH << 8 | nBitsTotalH >>> 24) & 0x00ff00ff | (nBitsTotalH << 24 | nBitsTotalH >>> 8) & 0xff00ff00;
          dataWords[(nBitsLeft + 64 >>> 9 << 4) + 14] = (nBitsTotalL << 8 | nBitsTotalL >>> 24) & 0x00ff00ff | (nBitsTotalL << 24 | nBitsTotalL >>> 8) & 0xff00ff00;
          data.sigBytes = (dataWords.length + 1) * 4;

          // Hash final blocks
          this._process();

          // Shortcuts
          var hash = this._hash;
          var H = hash.words;

          // Swap endian
          for (var _i2 = 0; _i2 < 4; _i2 += 1) {
            // Shortcut
            var H_i = H[_i2];
            H[_i2] = (H_i << 8 | H_i >>> 24) & 0x00ff00ff | (H_i << 24 | H_i >>> 8) & 0xff00ff00;
          }

          // Return final computed hash
          return hash;
        };
        _proto.clone = function clone() {
          var clone = _Hasher.prototype.clone.call(this);
          clone._hash = this._hash.clone();
          return clone;
        };
        return MD5Algo;
      }(Hasher));

      /**
       * Shortcut function to the hasher's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       *
       * @return {WordArray} The hash.
       *
       * @static
       *
       * @example
       *
       *     var hash = CryptoJS.MD5('message');
       *     var hash = CryptoJS.MD5(wordArray);
       */
      var MD5 = exports('MD5', Hasher._createHelper(MD5Algo));

      /**
       * Shortcut function to the HMAC's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       * @param {WordArray|string} key The secret key.
       *
       * @return {WordArray} The HMAC.
       *
       * @static
       *
       * @example
       *
       *     var hmac = CryptoJS.HmacMD5(message, key);
       */
      var HmacMD5 = exports('HmacMD5', Hasher._createHmacHelper(MD5Algo));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/MoveTile.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './MapManager.ts', './Resolver.ts', './Tile.ts', './GlobalData.ts'], function (exports) {
  var _inheritsLoose, cclegacy, _decorator, Vec2, MapManager, Resolver, Tile, TileType;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Vec2 = module.Vec2;
    }, function (module) {
      MapManager = module.MapManager;
    }, function (module) {
      Resolver = module.Resolver;
    }, function (module) {
      Tile = module.Tile;
    }, function (module) {
      TileType = module.TileType;
    }],
    execute: function () {
      var _dec, _class;
      cclegacy._RF.push({}, "4333dm+ehlEra5X105dKyJA", "MoveTile", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;

      //TODO::不同的物体会产生不同的阻力
      var MoveTile = exports('MoveTile', (_dec = ccclass('MoveTile'), _dec(_class = /*#__PURE__*/function (_Tile) {
        _inheritsLoose(MoveTile, _Tile);
        function MoveTile() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Tile.call.apply(_Tile, [this].concat(args)) || this;
          _this.moveDir = new Vec2();
          _this.slideDir = new Vec2();
          return _this;
        }
        var _proto = MoveTile.prototype;
        _proto.start = function start() {};
        _proto.flameHit = function flameHit(flame) {
          this.destroySelf();
        };
        _proto.slide = function slide() {
          if (this.slideDir.y != 0 || this.slideDir.x != 0) {
            this.prePos.set(this.node.x, this.node.y);
            this.node.y += this.slideDir.y;
            this.node.x += this.slideDir.x;
            if (this.slideDir.y > 0) {
              this.moveDir.set(0, 1);
              this.checkMoveUp();
            } else if (this.slideDir.y < 0) {
              this.moveDir.set(0, -1);
              this.checkMoveDown();
            }
            if (this.slideDir.x > 0) {
              this.moveDir.set(1, 0);
              this.checkMoveRight();
            } else if (this.slideDir.x < 0) {
              this.moveDir.set(-1, 0);
              this.checkMoveLeft();
            }
          }
        };
        _proto.checkMoveRight = function checkMoveRight() {
          var _this2 = this;
          var rightUp = MapManager.instance.getTiles(this.maxRow, this.maxCol);
          var rightDown = MapManager.instance.getTiles(this.minRow, this.maxCol);
          var checkTile = null;
          var minDx = 999; //如果有东西挡着就推不过去
          rightUp.forEach(function (tile) {
            if (tile == _this2) {
              return;
            }
            if (tile.collideRect.intersects(_this2.collideRect)) {
              var dx = _this2.collideRect.xMax - tile.collideRect.xMin;
              if (dx < minDx) {
                minDx = dx;
                checkTile = tile;
              }
            }
          });
          rightDown.forEach(function (tile) {
            if (tile == _this2) {
              return;
            }
            if (tile.collideRect.intersects(_this2.collideRect)) {
              var dx = _this2.collideRect.xMax - tile.collideRect.xMin;
              if (dx < minDx) {
                minDx = dx;
                checkTile = tile;
              }
            }
          });
          var isMove = false;
          if (checkTile) {
            if (checkTile.type == TileType.FLAME) {
              Resolver.instance.resolve(checkTile, this);
            } else {
              Resolver.instance.resolve(this, checkTile);
            }
            isMove = true;
          }
          this.updateMapPos();
          return isMove;
        };
        _proto.checkMoveLeft = function checkMoveLeft() {
          var _this3 = this;
          var leftUp = MapManager.instance.getTiles(this.maxRow, this.minCol);
          var leftDown = MapManager.instance.getTiles(this.minRow, this.minCol);
          var checkTile = null;
          var minDx = 999;
          leftUp.forEach(function (tile) {
            if (tile == _this3) {
              return;
            }
            if (tile.collideRect.intersects(_this3.collideRect)) {
              var dx = tile.collideRect.xMax - _this3.collideRect.xMin;
              if (dx < minDx) {
                minDx = dx;
                checkTile = tile;
              }
            }
          });
          leftDown.forEach(function (tile) {
            if (tile == _this3) {
              return;
            }
            if (tile.collideRect.intersects(_this3.collideRect)) {
              var dx = tile.collideRect.xMax - _this3.collideRect.xMin;
              if (dx < minDx) {
                minDx = dx;
                checkTile = tile;
              }
            }
          });
          var isMove = false;
          if (checkTile) {
            if (checkTile.type == TileType.FLAME) {
              Resolver.instance.resolve(checkTile, this);
            } else {
              Resolver.instance.resolve(this, checkTile);
            }
            isMove = true;
          }
          this.updateMapPos();
          return isMove;
        };
        _proto.checkMoveUp = function checkMoveUp() {
          var _this4 = this;
          var upLeft = MapManager.instance.getTiles(this.maxRow, this.minCol);
          var upRight = MapManager.instance.getTiles(this.maxRow, this.maxCol);
          var checkTile = null;
          var minDy = 999;
          upLeft.forEach(function (tile) {
            if (tile == _this4) {
              return;
            }
            if (tile.collideRect.intersects(_this4.collideRect)) {
              var dy = _this4.collideRect.yMax - tile.collideRect.yMin;
              if (dy < minDy) {
                minDy = dy;
                checkTile = tile;
              }
            }
          });
          upRight.forEach(function (tile) {
            if (tile == _this4) {
              return;
            }
            if (tile.collideRect.intersects(_this4.collideRect)) {
              var dy = _this4.collideRect.yMax - tile.collideRect.yMin;
              if (dy < minDy) {
                minDy = dy;
                checkTile = tile;
              }
            }
          });
          var isMove = false;
          if (checkTile) {
            if (checkTile.type == TileType.FLAME) {
              Resolver.instance.resolve(checkTile, this);
            } else {
              Resolver.instance.resolve(this, checkTile);
            }
            isMove = true;
          }
          this.updateMapPos();
          return isMove;
        };
        _proto.checkMoveDown = function checkMoveDown() {
          var _this5 = this;
          var downLeft = MapManager.instance.getTiles(this.minRow, this.minCol);
          var downRight = MapManager.instance.getTiles(this.minRow, this.maxCol);
          var checkTile = null;
          var minDy = 999;
          downLeft.forEach(function (tile) {
            if (tile == _this5) {
              return;
            }
            if (tile.collideRect.intersects(_this5.collideRect)) {
              var dy = tile.collideRect.yMax - _this5.collideRect.yMin;
              if (dy < minDy) {
                minDy = dy;
                checkTile = tile;
              }
            }
          });
          downRight.forEach(function (tile) {
            if (tile == _this5) {
              return;
            }
            if (tile.collideRect.intersects(_this5.collideRect)) {
              var dy = tile.collideRect.yMax - _this5.collideRect.yMin;
              if (dy < minDy) {
                minDy = dy;
                checkTile = tile;
              }
            }
          });
          var isMove = false;
          if (checkTile) {
            if (checkTile.type == TileType.FLAME) {
              Resolver.instance.resolve(checkTile, this);
            } else {
              Resolver.instance.resolve(this, checkTile);
            }
            isMove = true;
          }
          this.updateMapPos();
          return isMove;
        };
        return MoveTile;
      }(Tile)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/MoveTile1002.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './MoveTile.ts', './GlobalData.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, Animation, MoveTile, TileType;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Animation = module.Animation;
    }, function (module) {
      MoveTile = module.MoveTile;
    }, function (module) {
      TileType = module.TileType;
    }],
    execute: function () {
      var _dec, _dec2, _class, _class2, _descriptor;
      cclegacy._RF.push({}, "56694hOrZ5IKqQHBfbe36nV", "MoveTile1002", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var MoveTile1002 = exports('MoveTile1002', (_dec = ccclass('MoveTile1002'), _dec2 = property(Animation), _dec(_class = (_class2 = /*#__PURE__*/function (_MoveTile) {
        _inheritsLoose(MoveTile1002, _MoveTile);
        function MoveTile1002() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _MoveTile.call.apply(_MoveTile, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "animation", _descriptor, _assertThisInitialized(_this));
          return _this;
        }
        var _proto = MoveTile1002.prototype;
        _proto.start = function start() {};
        _proto.flameHit = function flameHit(flame) {
          if (this.isDead) return;
          this.isDead = true;
          this.type = TileType.STATIC;
          this.animation.play("movetile1002_die");
        };
        _proto.deadEnd = function deadEnd() {
          this.destroySelf();
        };
        _proto.update = function update(deltaTime) {};
        return MoveTile1002;
      }(MoveTile), _descriptor = _applyDecoratedDescriptor(_class2.prototype, "animation", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/PeerJS.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc'], function (exports) {
  var _createClass, cclegacy;
  return {
    setters: [function (module) {
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "b9f797c/0JB5I7Tk+CPMy5T", "PeerJS", undefined);
      var PeerJS = exports('PeerJS', /*#__PURE__*/function () {
        function PeerJS() {
          this.peerjs = void 0;
          this.peerjs = window["peerjs"];
        }
        var _proto = PeerJS.prototype;
        _proto.createPeer = function createPeer(id, options) {
          if (id === void 0) {
            id = null;
          }
          if (options === void 0) {
            options = null;
          }
          return new this.peerjs.Peer(id, options);
        };
        _createClass(PeerJS, null, [{
          key: "instance",
          get: function get() {
            if (!this._instance) {
              this._instance = new PeerJS();
            }
            return this._instance;
          }
        }]);
        return PeerJS;
      }());
      PeerJS._instance = null;
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Player.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './Tile.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, CCInteger, Vec2, Tile;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      CCInteger = module.CCInteger;
      Vec2 = module.Vec2;
    }, function (module) {
      Tile = module.Tile;
    }],
    execute: function () {
      var _dec, _dec2, _class, _class2, _descriptor;
      cclegacy._RF.push({}, "63891oNZH5Ni50ppPuh6lql", "Player", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var Player = exports('Player', (_dec = ccclass('Player'), _dec2 = property(CCInteger), _dec(_class = (_class2 = /*#__PURE__*/function (_Tile) {
        _inheritsLoose(Player, _Tile);
        function Player() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Tile.call.apply(_Tile, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "bombId", _descriptor, _assertThisInitialized(_this));
          _this.realDir = new Vec2();
          _this.dir = new Vec2();
          _this.slideDir = new Vec2();
          return _this;
        }
        return Player;
      }(Tile), _descriptor = _applyDecoratedDescriptor(_class2.prototype, "bombId", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return 0;
        }
      }), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Player100.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BombCreator.ts', './Player.ts', './StateMachine.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, Animation, input, Input, log, KeyCode, BombCreator, Player, StateMachine;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Animation = module.Animation;
      input = module.input;
      Input = module.Input;
      log = module.log;
      KeyCode = module.KeyCode;
    }, function (module) {
      BombCreator = module.BombCreator;
    }, function (module) {
      Player = module.Player;
    }, function (module) {
      StateMachine = module.StateMachine;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _class, _class2, _descriptor, _descriptor2;
      cclegacy._RF.push({}, "79c9ajZ6wRL7pUOpiwNe4p0", "Player100", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var Player100 = exports('Player100', (_dec = ccclass('Player100'), _dec2 = property(Animation), _dec3 = property(StateMachine), _dec(_class = (_class2 = /*#__PURE__*/function (_Player) {
        _inheritsLoose(Player100, _Player);
        function Player100() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Player.call.apply(_Player, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "animation", _descriptor, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "stateMachine", _descriptor2, _assertThisInitialized(_this));
          return _this;
        }
        var _proto = Player100.prototype;
        _proto.start = function start() {
          input.on(Input.EventType.KEY_DOWN, this.onKeyDown, this);
          input.on(Input.EventType.KEY_UP, this.onKeyUp, this);
          this.stateMachine.setStateByName("StatePlayer100Idle");
        };
        _proto.flameHit = function flameHit(flame) {
          //撞到了会怎么样
          log("hit");
        };
        _proto.playerAnimation = function playerAnimation(animationName) {
          var state = this.animation.getState(animationName);
          if (!state.isPlaying) {
            this.animation.play(animationName);
          }
        };
        _proto.onKeyDown = function onKeyDown(event) {
          switch (event.keyCode) {
            case KeyCode.ARROW_UP:
              this.dir.y = 1;
              break;
            case KeyCode.ARROW_DOWN:
              this.dir.y = -1;
              break;
            case KeyCode.ARROW_LEFT:
              this.dir.x = -1;
              break;
            case KeyCode.ARROW_RIGHT:
              this.dir.x = 1;
              break;
            case KeyCode.SPACE:
              this.createBoom();
              break;
          }
        };
        _proto.onKeyUp = function onKeyUp(event) {
          switch (event.keyCode) {
            case KeyCode.ARROW_UP:
              if (this.dir.y == 1) {
                this.dir.y = 0;
              }
              break;
            case KeyCode.ARROW_DOWN:
              if (this.dir.y == -1) {
                this.dir.y = 0;
              }
              break;
            case KeyCode.ARROW_LEFT:
              if (this.dir.x == -1) {
                this.dir.x = 0;
              }
              break;
            case KeyCode.ARROW_RIGHT:
              if (this.dir.x == 1) {
                this.dir.x = 0;
              }
              break;
          }
        };
        _proto.createBoom = function createBoom() {
          BombCreator.instance.create(this);
        };
        _proto.update = function update(deltaTime) {
          if (this.stateMachine) {
            this.stateMachine.updateData(deltaTime);
          }
        };
        return Player100;
      }(Player), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "animation", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "stateMachine", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      })), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Player101.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BombCreator.ts', './Player.ts', './StateMachine.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, sp, Vec2, input, Input, log, KeyCode, BombCreator, Player, StateMachine;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      sp = module.sp;
      Vec2 = module.Vec2;
      input = module.input;
      Input = module.Input;
      log = module.log;
      KeyCode = module.KeyCode;
    }, function (module) {
      BombCreator = module.BombCreator;
    }, function (module) {
      Player = module.Player;
    }, function (module) {
      StateMachine = module.StateMachine;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _class, _class2, _descriptor, _descriptor2;
      cclegacy._RF.push({}, "e332aIaEutG+7natHlTVRtQ", "Player101", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var Player101 = exports('Player101', (_dec = ccclass('Player101'), _dec2 = property(sp.Skeleton), _dec3 = property(StateMachine), _dec(_class = (_class2 = /*#__PURE__*/function (_Player) {
        _inheritsLoose(Player101, _Player);
        function Player101() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Player.call.apply(_Player, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "skeleton", _descriptor, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "stateMachine", _descriptor2, _assertThisInitialized(_this));
          _this.faceTo = new Vec2(0, -1);
          return _this;
        }
        var _proto = Player101.prototype;
        _proto.start = function start() {
          input.on(Input.EventType.KEY_DOWN, this.onKeyDown, this);
          input.on(Input.EventType.KEY_UP, this.onKeyUp, this);
          this.stateMachine.setStateByName("StatePlayer101Idle");
        };
        _proto.flameHit = function flameHit(flame) {
          //撞到了会怎么样
          log("hit");
        };
        _proto.playAnimation = function playAnimation(animationName, loop) {
          if (loop === void 0) {
            loop = true;
          }
          var track = this.skeleton.getCurrent(0);
          if (track.animation.name != animationName) {
            this.skeleton.setAnimation(0, animationName, loop);
          }
        };
        _proto.onKeyDown = function onKeyDown(event) {
          switch (event.keyCode) {
            case KeyCode.ARROW_UP:
              this.dir.y = 1;
              break;
            case KeyCode.ARROW_DOWN:
              this.dir.y = -1;
              break;
            case KeyCode.ARROW_LEFT:
              this.dir.x = -1;
              break;
            case KeyCode.ARROW_RIGHT:
              this.dir.x = 1;
              break;
            case KeyCode.SPACE:
              this.createBoom();
              break;
          }
        };
        _proto.onKeyUp = function onKeyUp(event) {
          switch (event.keyCode) {
            case KeyCode.ARROW_UP:
              if (this.dir.y == 1) {
                this.dir.y = 0;
              }
              break;
            case KeyCode.ARROW_DOWN:
              if (this.dir.y == -1) {
                this.dir.y = 0;
              }
              break;
            case KeyCode.ARROW_LEFT:
              if (this.dir.x == -1) {
                this.dir.x = 0;
              }
              break;
            case KeyCode.ARROW_RIGHT:
              if (this.dir.x == 1) {
                this.dir.x = 0;
              }
              break;
          }
        };
        _proto.createBoom = function createBoom() {
          BombCreator.instance.create(this);
        };
        _proto.update = function update(deltaTime) {
          if (this.stateMachine) {
            this.stateMachine.updateData(deltaTime);
          }
        };
        return Player101;
      }(Player), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "skeleton", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "stateMachine", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      })), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/PlayerConfigPanel.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './EventManager.ts', './ConfigRole.ts', './GlobalData.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, log, Component, EventManager, ConfigRole, PlayerSlotType;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      log = module.log;
      Component = module.Component;
    }, function (module) {
      EventManager = module.EventManager;
    }, function (module) {
      ConfigRole = module.ConfigRole;
    }, function (module) {
      PlayerSlotType = module.PlayerSlotType;
    }],
    execute: function () {
      var _dec, _dec2, _class, _class2, _descriptor;
      cclegacy._RF.push({}, "73944KK/nlCAah+HghQfqMz", "PlayerConfigPanel", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var PlayerConfigPanel = exports('PlayerConfigPanel', (_dec = ccclass('PlayerConfigPanel'), _dec2 = property(ConfigRole), _dec(_class = (_class2 = /*#__PURE__*/function (_Component) {
        _inheritsLoose(PlayerConfigPanel, _Component);
        function PlayerConfigPanel() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Component.call.apply(_Component, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "configRole", _descriptor, _assertThisInitialized(_this));
          return _this;
        }
        var _proto = PlayerConfigPanel.prototype;
        _proto.start = function start() {
          EventManager.instance.on(EventManager.ITEM_ICON_CLICK, this.onItemIconClick, this);
        };
        _proto.onItemIconClick = function onItemIconClick(itemId) {
          log("item icon click::", itemId);
          if (itemId == 11) {
            this.configRole.setAvatar(PlayerSlotType.CAP, itemId);
          } else if (itemId == 12) {
            this.configRole.setAvatar(PlayerSlotType.COAT, itemId);
          }
        };
        _proto.show = function show() {
          this.node.active = true;
        };
        _proto.hide = function hide() {
          this.node.active = false;
        };
        _proto.update = function update(deltaTime) {};
        return PlayerConfigPanel;
      }(Component), _descriptor = _applyDecoratedDescriptor(_class2.prototype, "configRole", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/PlayerSlot.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, Sprite, Component;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Sprite = module.Sprite;
      Component = module.Component;
    }],
    execute: function () {
      var _dec, _dec2, _class, _class2, _descriptor;
      cclegacy._RF.push({}, "53315Scq8VI8rYZq+DsGK2D", "PlayerSlot", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var PlayerSlot = exports('PlayerSlot', (_dec = ccclass('PlayerSlot'), _dec2 = property(Sprite), _dec(_class = (_class2 = /*#__PURE__*/function (_Component) {
        _inheritsLoose(PlayerSlot, _Component);
        function PlayerSlot() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Component.call.apply(_Component, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "icon", _descriptor, _assertThisInitialized(_this));
          _this.type = void 0;
          return _this;
        }
        var _proto = PlayerSlot.prototype;
        _proto.start = function start() {};
        _proto.setIcon = function setIcon(spriteFrame) {
          this.icon.spriteFrame = spriteFrame;
        };
        _proto.update = function update(deltaTime) {};
        return PlayerSlot;
      }(Component), _descriptor = _applyDecoratedDescriptor(_class2.prototype, "icon", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Preload.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './GlobalData.ts', './ResourceManager.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, Sprite, Label, log, AudioClip, JsonAsset, SpriteFrame, Prefab, director, Component, BundleType, ResourceManager;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Sprite = module.Sprite;
      Label = module.Label;
      log = module.log;
      AudioClip = module.AudioClip;
      JsonAsset = module.JsonAsset;
      SpriteFrame = module.SpriteFrame;
      Prefab = module.Prefab;
      director = module.director;
      Component = module.Component;
    }, function (module) {
      BundleType = module.BundleType;
    }, function (module) {
      ResourceManager = module.ResourceManager;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _class, _class2, _descriptor, _descriptor2;
      cclegacy._RF.push({}, "3ce4f0mZeJN47vI7j92fi9O", "Preload", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var Preload = exports('Preload', (_dec = ccclass('Preload'), _dec2 = property(Sprite), _dec3 = property(Label), _dec(_class = (_class2 = /*#__PURE__*/function (_Component) {
        _inheritsLoose(Preload, _Component);
        function Preload() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Component.call.apply(_Component, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "bar", _descriptor, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "percent", _descriptor2, _assertThisInitialized(_this));
          _this.subPackages = ["ab_textures", "ab_prefabs", "ab_data"];
          _this.top = 0;
          _this.current = 0;
          _this.isOver = false;
          _this.total = 4;
          return _this;
        }
        var _proto = Preload.prototype;
        _proto.start = function start() {
          // this.bar.fillRange = 0.0;
          // this.percent.string = "0%";
          this.loadSubPackages();
        };
        _proto.loadSubPackages = function loadSubPackages() {
          for (var i = 0; i < this.subPackages.length; ++i) {
            var bundleName = this.subPackages[i];
            ResourceManager.instance.addBundles(bundleName);
          }
          ResourceManager.instance.loadBundles("BunldLoaded", this.node);
          this.node.on("BunldLoaded", this.onBundleLoaded, this);
        };
        _proto.onBundleLoaded = function onBundleLoaded() {
          log("bundle loaded...");
          this.node.off("BunldLoaded");
          this.top += 1;

          // this.loadLocalData();
          this.loadPrefabs();
          this.loadData();
          this.loadTextures();
          // this.loadSounds();
        };

        _proto.onSceneLoaded = function onSceneLoaded() {
          log("scene loaded...");
          this.top += 1;
        };
        _proto.loadSounds = function loadSounds() {
          var batch = ResourceManager.instance.createNewBatch("SoundsLoaded", "SoundsLoaded", this.node);
          batch.addResource("./", "ab_sounds", BundleType.Asset, AudioClip, "", null, ["dir"]);
          this.node.on("SoundsLoaded", this.onSoundsLoaded, this);
          batch.start();
        };
        _proto.onSoundsLoaded = function onSoundsLoaded() {
          log("sounds loaded...");
          this.node.off("SoundsLoaded");
          this.top += 1;
        };
        _proto.loadLocalData = function loadLocalData() {};
        _proto.loadData = function loadData() {
          var batch = ResourceManager.instance.createNewBatch("DataLoaded", "DataLoaded", this.node);
          batch.addResource("./", "ab_data", BundleType.Asset, JsonAsset, "", null, ["dir"]);
          // batch.addResource(`packs`, "ab_data", BundleType.Asset, JsonAsset);
          // batch.addResource(`puzzles`, "ab_data", BundleType.Asset, JsonAsset);
          // batch.addResource(`shop`, "ab_data", BundleType.Asset, JsonAsset);
          this.node.on("DataLoaded", this.onDataLoaded, this);
          batch.start();
        };
        _proto.onDataLoaded = function onDataLoaded() {
          log("data loaded...");
          this.node.off("DataLoaded");
          this.top += 1;
        };
        _proto.loadTextures = function loadTextures() {
          var batch = ResourceManager.instance.createNewBatch("TexturesLoaded", "TexturesLoaded", this.node);
          batch.addResource("./", "ab_textures", BundleType.Asset, SpriteFrame, "", null, ["dir"]);
          this.node.on("TexturesLoaded", this.onTexturesLoaded, this);
          batch.start();
        };
        _proto.onTexturesLoaded = function onTexturesLoaded() {
          log("textures loaded...");
          this.node.off("TexturesLoaded");
          this.top += 1;
          // let spriteFrame:SpriteFrame = ResourceManager.instance.getAsset(`items/icons/${11}/spriteFrame`, "ab_textures", SpriteFrame) as SpriteFrame;
          // log(spriteFrame);
        };

        _proto.loadPrefabs = function loadPrefabs() {
          var batch = ResourceManager.instance.createNewBatch("PrefabsLoaded", "PrefabsLoaded", this.node);
          batch.addResource("others", "ab_prefabs", BundleType.Asset, Prefab, "", null, ["dir"]);
          batch.addResource("tiles", "ab_prefabs", BundleType.Asset, Prefab, "", null, ["dir"]);
          this.node.on("PrefabsLoaded", this.onPrefabsLoaded, this);
          batch.start();
        };
        _proto.onPrefabsLoaded = function onPrefabsLoaded() {
          log("prefab loaded...");
          this.node.off("PrefabsLoaded");
          this.top += 1;

          // let PlayerPrefab = ResourceManager.instance.getAsset("others/Player", "ab_prefabs", Prefab) as Prefab;
          // let playerNode = instantiate(PlayerPrefab);
          // let player = playerNode.getComponent(Tile);
          // log(player);
        };

        _proto.checkPrecent = function checkPrecent(dt) {
          if (this.top == this.total) {
            //已经完成了
            this.current += 0.1;
            if (this.current >= this.total) {
              this.current = this.total;
              this.isOver = true;
            }
          } else {
            var map_speed = this.top - this.current;
            if (map_speed < 0) {
              map_speed = 0;
            }
            this.current += map_speed * dt;
          }
          // let progress = this.current / this.total;
          // this.bar.fillRange = progress;
          // this.percent.string = `${Math.floor(progress * 100)}%`;
          if (this.isOver) {
            director.loadScene("Test");
          }
        };
        _proto.update = function update(deltaTime) {
          if (this.isOver) return;
          this.checkPrecent(deltaTime);
        };
        return Preload;
      }(Component), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "bar", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "percent", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      })), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/ResolveBase.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "173cfCdzD9N5Y8ewkv9O3ft", "ResolveBase", undefined);
      var ResolveBase = exports('ResolveBase', /*#__PURE__*/function () {
        function ResolveBase() {}
        var _proto = ResolveBase.prototype;
        _proto.resolve = function resolve(tile1, tile2) {};
        return ResolveBase;
      }());
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/ResolveMoveBlock.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './GlobalData.ts', './MapManager.ts', './ResolveBase.ts'], function (exports) {
  var _inheritsLoose, _createForOfIteratorHelperLoose, cclegacy, GlobalData, TileType, MapManager, ResolveBase;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
      _createForOfIteratorHelperLoose = module.createForOfIteratorHelperLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      GlobalData = module.GlobalData;
      TileType = module.TileType;
    }, function (module) {
      MapManager = module.MapManager;
    }, function (module) {
      ResolveBase = module.ResolveBase;
    }],
    execute: function () {
      cclegacy._RF.push({}, "2e17bE7oMJB/Yejl8n641UJ", "ResolveMoveBlock", undefined);
      var ResolveMoveBlock = exports('ResolveMoveBlock', /*#__PURE__*/function (_ResolveBase) {
        _inheritsLoose(ResolveMoveBlock, _ResolveBase);
        function ResolveMoveBlock() {
          var _this;
          _this = _ResolveBase.call(this) || this;
          _this.blockSlideTypes = [TileType.STATIC, TileType.BOMB, TileType.MOVE, TileType.ENEMY];
          return _this;
        }
        var _proto = ResolveMoveBlock.prototype;
        _proto.resolve = function resolve(moveTile, blockTile) {
          this.checkRight(moveTile, blockTile);
          this.checkLeft(moveTile, blockTile);
          this.checkUp(moveTile, blockTile);
          this.checkDown(moveTile, blockTile);
        };
        _proto.checkRight = function checkRight(moveTile, blockTile) {
          if (moveTile.moveDir.x != 1) {
            return;
          }
          if (moveTile.collideRect.intersects(blockTile.collideRect)) {
            var rightDown = MapManager.instance.getTiles(moveTile.minRow, moveTile.maxCol);
            if (moveTile.collideRect.yMax - blockTile.collideRect.yMin < GlobalData.TILE_HEIGHT * 0.5 && !this.blockToSlide(rightDown, moveTile, this.blockSlideTypes)) {
              moveTile.slideDir.y = -1;
              moveTile.slide();
            }
            var rightUp = MapManager.instance.getTiles(moveTile.maxRow, moveTile.maxCol);
            if (blockTile.collideRect.yMax - moveTile.collideRect.yMin < GlobalData.TILE_HEIGHT * 0.5 && !this.blockToSlide(rightUp, moveTile, this.blockSlideTypes)) {
              moveTile.slideDir.y = 1;
              moveTile.slide();
            }
            var dx = blockTile.collideRect.xMin - moveTile.collideRect.xMax;
            moveTile.node.x = moveTile.node.x + dx - 1;
          }
        };
        _proto.checkLeft = function checkLeft(moveTile, blockTile) {
          if (moveTile.moveDir.x != -1) {
            return;
          }
          if (moveTile.collideRect.intersects(blockTile.collideRect)) {
            var leftDown = MapManager.instance.getTiles(moveTile.minRow, moveTile.minCol);
            if (moveTile.collideRect.yMax - blockTile.collideRect.yMin < GlobalData.TILE_HEIGHT * 0.5 && !this.blockToSlide(leftDown, moveTile, this.blockSlideTypes)) {
              moveTile.slideDir.y = -1;
              moveTile.slide();
            }
            var leftUp = MapManager.instance.getTiles(moveTile.maxRow, moveTile.minCol);
            if (blockTile.collideRect.yMax - moveTile.collideRect.yMin < GlobalData.TILE_HEIGHT * 0.5 && !this.blockToSlide(leftUp, moveTile, this.blockSlideTypes)) {
              moveTile.slideDir.y = 1;
              moveTile.slide();
            }
            var dx = blockTile.collideRect.xMax - moveTile.collideRect.xMin;
            moveTile.node.x = moveTile.node.x + dx + 1;
          }
        };
        _proto.checkUp = function checkUp(moveTile, blockTile) {
          if (moveTile.moveDir.y != 1) {
            return;
          }
          if (moveTile.collideRect.intersects(blockTile.collideRect)) {
            var leftUp = MapManager.instance.getTiles(moveTile.maxRow, moveTile.minCol);
            if (moveTile.collideRect.xMax - blockTile.collideRect.xMin < GlobalData.TILE_WIDTH * 0.5 && !this.blockToSlide(leftUp, moveTile, this.blockSlideTypes)) {
              moveTile.slideDir.x = -1;
              moveTile.slide();
            }
            var rightUp = MapManager.instance.getTiles(moveTile.maxRow, moveTile.maxCol);
            if (blockTile.collideRect.xMax - moveTile.collideRect.xMin < GlobalData.TILE_WIDTH * 0.5 && !this.blockToSlide(rightUp, moveTile, this.blockSlideTypes)) {
              moveTile.slideDir.x = 1;
              moveTile.slide();
            }
            var dy = blockTile.collideRect.yMin - moveTile.collideRect.yMax;
            moveTile.node.y = moveTile.node.y + dy - 1;
          }
        };
        _proto.checkDown = function checkDown(moveTile, blockTile) {
          if (moveTile.moveDir.y != -1) {
            return;
          }
          if (moveTile.collideRect.intersects(blockTile.collideRect)) {
            var leftDown = MapManager.instance.getTiles(moveTile.minRow, moveTile.minCol);
            if (moveTile.collideRect.xMax - blockTile.collideRect.xMin < GlobalData.TILE_WIDTH * 0.5 && !this.blockToSlide(leftDown, moveTile, this.blockSlideTypes)) {
              moveTile.slideDir.x = -1;
              moveTile.slide();
            }
            var rightDown = MapManager.instance.getTiles(moveTile.minRow, moveTile.maxCol);
            if (blockTile.collideRect.xMax - moveTile.collideRect.xMin < GlobalData.TILE_WIDTH * 0.5 && !this.blockToSlide(rightDown, moveTile, this.blockSlideTypes)) {
              moveTile.slideDir.x = 1;
              moveTile.slide();
            }
            var dy = blockTile.collideRect.yMax - moveTile.collideRect.yMin;
            moveTile.node.y = moveTile.node.y + dy + 1;
          }
        };
        _proto.blockToSlide = function blockToSlide(tiles, moveTile, types) {
          for (var _iterator = _createForOfIteratorHelperLoose(types), _step; !(_step = _iterator()).done;) {
            var type = _step.value;
            if (MapManager.instance.hasExcludeType(tiles, moveTile, type)) {
              return true;
            }
          }
          return false;
        };
        return ResolveMoveBlock;
      }(ResolveBase));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/ResolvePlayerBomb.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './GlobalData.ts', './MapManager.ts', './ResolveBase.ts'], function (exports) {
  var _inheritsLoose, _createForOfIteratorHelperLoose, cclegacy, GlobalData, TileType, MapManager, ResolveBase;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
      _createForOfIteratorHelperLoose = module.createForOfIteratorHelperLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      GlobalData = module.GlobalData;
      TileType = module.TileType;
    }, function (module) {
      MapManager = module.MapManager;
    }, function (module) {
      ResolveBase = module.ResolveBase;
    }],
    execute: function () {
      cclegacy._RF.push({}, "28360WAHlhItaV0v9b9DPYb", "ResolvePlayerBomb", undefined);
      var ResolvePlayerBomb = exports('ResolvePlayerBomb', /*#__PURE__*/function (_ResolveBase) {
        _inheritsLoose(ResolvePlayerBomb, _ResolveBase);
        function ResolvePlayerBomb() {
          var _this;
          _this = _ResolveBase.call(this) || this;
          _this.blockSlideTypes = [TileType.STATIC, TileType.BOMB];
          return _this;
        }
        var _proto = ResolvePlayerBomb.prototype;
        _proto.resolve = function resolve(player, bomb) {
          this.checkRight(player, bomb);
          this.checkLeft(player, bomb);
          this.checkUp(player, bomb);
          this.checkDown(player, bomb);
        };
        _proto.checkRight = function checkRight(player, bomb) {
          if (player.realDir.x != 1) {
            return;
          }
          if ((player.maxRowPre == bomb.minRow || player.minRowPre == bomb.minRow) && player.maxColPre == bomb.minCol) {
            return;
          }
          if (player.collideRect.intersects(bomb.collideRect)) {
            var rightDown = MapManager.instance.getTiles(player.minRow, player.maxCol);
            if (player.collideRect.yMax - bomb.collideRect.yMin < GlobalData.TILE_HEIGHT * 0.5 && !this.blockToSlide(rightDown, this.blockSlideTypes)) {
              player.slideDir.y = -1;
            }
            var rightUp = MapManager.instance.getTiles(player.maxRow, player.maxCol);
            if (bomb.collideRect.yMax - player.collideRect.yMin < GlobalData.TILE_HEIGHT * 0.5 && !this.blockToSlide(rightUp, this.blockSlideTypes)) {
              player.slideDir.y = 1;
            }
            var dx = bomb.collideRect.xMin - player.collideRect.xMax;
            player.node.x = player.node.x + dx - 1;
          }
        };
        _proto.checkLeft = function checkLeft(player, bomb) {
          if (player.realDir.x != -1) {
            return;
          }
          if ((player.maxRowPre == bomb.minRow || player.minRowPre == bomb.minRow) && player.minColPre == bomb.maxCol) {
            return;
          }
          if (player.collideRect.intersects(bomb.collideRect)) {
            var leftDown = MapManager.instance.getTiles(player.minRow, player.minCol);
            if (player.collideRect.yMax - bomb.collideRect.yMin < GlobalData.TILE_HEIGHT * 0.5 && !this.blockToSlide(leftDown, this.blockSlideTypes)) {
              player.slideDir.y = -1;
            }
            var leftUp = MapManager.instance.getTiles(player.maxRow, player.minCol);
            if (bomb.collideRect.yMax - player.collideRect.yMin < GlobalData.TILE_HEIGHT * 0.5 && !this.blockToSlide(leftUp, this.blockSlideTypes)) {
              player.slideDir.y = 1;
            }
            var dx = bomb.collideRect.xMax - player.collideRect.xMin;
            player.node.x = player.node.x + dx + 1;
          }
        };
        _proto.checkUp = function checkUp(player, bomb) {
          if (player.realDir.y != 1) {
            return;
          }
          if ((player.maxColPre == bomb.minCol || player.minColPre == bomb.minCol) && player.maxRowPre == bomb.minRow) {
            return;
          }
          if (player.collideRect.intersects(bomb.collideRect)) {
            var leftUp = MapManager.instance.getTiles(player.maxRow, player.minCol);
            if (player.collideRect.xMax - bomb.collideRect.xMin < GlobalData.TILE_WIDTH * 0.5 && !this.blockToSlide(leftUp, this.blockSlideTypes)) {
              player.slideDir.x = -1;
            }
            var rightUp = MapManager.instance.getTiles(player.maxRow, player.maxCol);
            if (bomb.collideRect.xMax - player.collideRect.xMin < GlobalData.TILE_WIDTH * 0.5 && !this.blockToSlide(rightUp, this.blockSlideTypes)) {
              player.slideDir.x = 1;
            }
            var dy = bomb.collideRect.yMin - player.collideRect.yMax;
            player.node.y = player.node.y + dy - 1;
          }
        };
        _proto.checkDown = function checkDown(player, bomb) {
          if (player.realDir.y != -1) {
            return;
          }
          if ((player.maxColPre == bomb.minCol || player.minColPre == bomb.minCol) && player.minRowPre == bomb.maxRow) {
            return;
          }
          if (player.collideRect.intersects(bomb.collideRect)) {
            var leftDown = MapManager.instance.getTiles(player.minRow, player.minCol);
            if (player.collideRect.xMax - bomb.collideRect.xMin < GlobalData.TILE_WIDTH * 0.5 && !this.blockToSlide(leftDown, this.blockSlideTypes)) {
              player.slideDir.x = -1;
            }
            var rightDown = MapManager.instance.getTiles(player.minRow, player.maxCol);
            if (bomb.collideRect.xMax - player.collideRect.xMin < GlobalData.TILE_WIDTH * 0.5 && !this.blockToSlide(rightDown, this.blockSlideTypes)) {
              player.slideDir.x = 1;
            }
            var dy = bomb.collideRect.yMax - player.collideRect.yMin;
            player.node.y = player.node.y + dy + 1;
          }
        };
        _proto.blockToSlide = function blockToSlide(tiles, types) {
          for (var _iterator = _createForOfIteratorHelperLoose(types), _step; !(_step = _iterator()).done;) {
            var type = _step.value;
            if (MapManager.instance.hasType(tiles, type)) {
              return true;
            }
          }
          return false;
        };
        return ResolvePlayerBomb;
      }(ResolveBase));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/ResolvePlayerStatic.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './GlobalData.ts', './MapManager.ts', './ResolveBase.ts'], function (exports) {
  var _inheritsLoose, _createForOfIteratorHelperLoose, cclegacy, GlobalData, TileType, MapManager, ResolveBase;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
      _createForOfIteratorHelperLoose = module.createForOfIteratorHelperLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      GlobalData = module.GlobalData;
      TileType = module.TileType;
    }, function (module) {
      MapManager = module.MapManager;
    }, function (module) {
      ResolveBase = module.ResolveBase;
    }],
    execute: function () {
      cclegacy._RF.push({}, "7089bygPytK+JZMthhy3s6s", "ResolvePlayerStatic", undefined);

      //Player和阻挡的物体碰撞应该怎么弄
      var ResolvePlayerStatic = exports('ResolvePlayerStatic', /*#__PURE__*/function (_ResolveBase) {
        _inheritsLoose(ResolvePlayerStatic, _ResolveBase);
        function ResolvePlayerStatic() {
          var _this;
          _this = _ResolveBase.call(this) || this;
          _this.blockSlideTypes = [TileType.STATIC, TileType.BOMB];
          return _this;
        }
        var _proto = ResolvePlayerStatic.prototype;
        _proto.resolve = function resolve(player, blockTile) {
          this.checkRight(player, blockTile);
          this.checkLeft(player, blockTile);
          this.checkUp(player, blockTile);
          this.checkDown(player, blockTile);
        };
        _proto.checkRight = function checkRight(player, blockTile) {
          if (player.realDir.x != 1) {
            return;
          }
          if (player.collideRect.intersects(blockTile.collideRect)) {
            var rightDown = MapManager.instance.getTiles(player.minRow, player.maxCol);
            if (player.collideRect.yMax - blockTile.collideRect.yMin < GlobalData.TILE_HEIGHT * 0.5 && !this.blockToSlide(rightDown, this.blockSlideTypes)) {
              player.slideDir.y = -1;
            }
            var rightUp = MapManager.instance.getTiles(player.maxRow, player.maxCol);
            if (blockTile.collideRect.yMax - player.collideRect.yMin < GlobalData.TILE_HEIGHT * 0.5 && !this.blockToSlide(rightUp, this.blockSlideTypes)) {
              player.slideDir.y = 1;
            }
            var dx = blockTile.collideRect.xMin - player.collideRect.xMax;
            player.node.x = player.node.x + dx - 1;
          }
        };
        _proto.checkLeft = function checkLeft(player, blockTile) {
          if (player.realDir.x != -1) {
            return;
          }
          if (player.collideRect.intersects(blockTile.collideRect)) {
            var leftDown = MapManager.instance.getTiles(player.minRow, player.minCol);
            if (player.collideRect.yMax - blockTile.collideRect.yMin < GlobalData.TILE_HEIGHT * 0.5 && !this.blockToSlide(leftDown, this.blockSlideTypes)) {
              player.slideDir.y = -1;
            }
            var leftUp = MapManager.instance.getTiles(player.maxRow, player.minCol);
            if (blockTile.collideRect.yMax - player.collideRect.yMin < GlobalData.TILE_HEIGHT * 0.5 && !this.blockToSlide(leftUp, this.blockSlideTypes)) {
              player.slideDir.y = 1;
            }
            var dx = blockTile.collideRect.xMax - player.collideRect.xMin;
            player.node.x = player.node.x + dx + 1;
          }
        };
        _proto.checkUp = function checkUp(player, blockTile) {
          if (player.realDir.y != 1) {
            return;
          }
          if (player.collideRect.intersects(blockTile.collideRect)) {
            var leftUp = MapManager.instance.getTiles(player.maxRow, player.minCol);
            if (player.collideRect.xMax - blockTile.collideRect.xMin < GlobalData.TILE_WIDTH * 0.5 && !this.blockToSlide(leftUp, this.blockSlideTypes)) {
              player.slideDir.x = -1;
            }
            var rightUp = MapManager.instance.getTiles(player.maxRow, player.maxCol);
            if (blockTile.collideRect.xMax - player.collideRect.xMin < GlobalData.TILE_WIDTH * 0.5 && !this.blockToSlide(rightUp, this.blockSlideTypes)) {
              player.slideDir.x = 1;
            }
            var dy = blockTile.collideRect.yMin - player.collideRect.yMax;
            player.node.y = player.node.y + dy - 1;
          }
        };
        _proto.checkDown = function checkDown(player, blockTile) {
          if (player.realDir.y != -1) {
            return;
          }
          if (player.collideRect.intersects(blockTile.collideRect)) {
            var leftDown = MapManager.instance.getTiles(player.minRow, player.minCol);
            if (player.collideRect.xMax - blockTile.collideRect.xMin < GlobalData.TILE_WIDTH * 0.5 && !this.blockToSlide(leftDown, this.blockSlideTypes)) {
              player.slideDir.x = -1;
            }
            var rightDown = MapManager.instance.getTiles(player.minRow, player.maxCol);
            if (blockTile.collideRect.xMax - player.collideRect.xMin < GlobalData.TILE_WIDTH * 0.5 && !this.blockToSlide(rightDown, this.blockSlideTypes)) {
              player.slideDir.x = 1;
            }
            var dy = blockTile.collideRect.yMax - player.collideRect.yMin;
            player.node.y = player.node.y + dy + 1;
          }
        };
        _proto.blockToSlide = function blockToSlide(tiles, types) {
          for (var _iterator = _createForOfIteratorHelperLoose(types), _step; !(_step = _iterator()).done;) {
            var type = _step.value;
            if (MapManager.instance.hasType(tiles, type)) {
              return true;
            }
          }
          return false;
        };
        return ResolvePlayerStatic;
      }(ResolveBase));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Resolver.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './GlobalData.ts', './ResolveMoveBlock.ts', './ResolvePlayerBomb.ts', './ResolvePlayerStatic.ts', './ResovleFlameTile.ts', './ResovlePlayerMove.ts'], function (exports) {
  var _createClass, cclegacy, TileType, ResolveMoveBlock, ResolvePlayerBomb, ResolvePlayerStatic, ResovleFlameTile, ResovlePlayerMove;
  return {
    setters: [function (module) {
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      TileType = module.TileType;
    }, function (module) {
      ResolveMoveBlock = module.ResolveMoveBlock;
    }, function (module) {
      ResolvePlayerBomb = module.ResolvePlayerBomb;
    }, function (module) {
      ResolvePlayerStatic = module.ResolvePlayerStatic;
    }, function (module) {
      ResovleFlameTile = module.ResovleFlameTile;
    }, function (module) {
      ResovlePlayerMove = module.ResovlePlayerMove;
    }],
    execute: function () {
      cclegacy._RF.push({}, "afad4boWO9IhqlLWpBgxIGN", "Resolver", undefined);
      var ResolveType = /*#__PURE__*/function (ResolveType) {
        ResolveType[ResolveType["PLAYER_STATIC"] = 0] = "PLAYER_STATIC";
        ResolveType[ResolveType["PLAYER_MOVE"] = 1] = "PLAYER_MOVE";
        ResolveType[ResolveType["PLAYER_BOMB"] = 2] = "PLAYER_BOMB";
        ResolveType[ResolveType["MOVE_BLOCK"] = 3] = "MOVE_BLOCK";
        ResolveType[ResolveType["FLAME_TILE"] = 4] = "FLAME_TILE";
        return ResolveType;
      }(ResolveType || {}); //两个碰撞体碰撞后的解决器，就是它们碰撞后各自应该怎么运动。
      var Resolver = exports('Resolver', /*#__PURE__*/function () {
        function Resolver() {
          this.list = [];
          this.list[ResolveType.PLAYER_STATIC] = new ResolvePlayerStatic();
          this.list[ResolveType.PLAYER_MOVE] = new ResovlePlayerMove();
          this.list[ResolveType.PLAYER_BOMB] = new ResolvePlayerBomb();
          this.list[ResolveType.MOVE_BLOCK] = new ResolveMoveBlock();
          this.list[ResolveType.FLAME_TILE] = new ResovleFlameTile();
        }
        var _proto = Resolver.prototype;
        _proto.resolve = function resolve(tile1, tile2) {
          if (tile1.type == TileType.PLAYER && tile2.type == TileType.STATIC) {
            this.list[ResolveType.PLAYER_STATIC].resolve(tile1, tile2);
          } else if (tile1.type == TileType.PLAYER && tile2.type == TileType.MOVE) {
            this.list[ResolveType.PLAYER_MOVE].resolve(tile1, tile2);
          } else if (tile1.type == TileType.MOVE && (tile2.type == TileType.STATIC || tile2.type == TileType.MOVE || tile2.type == TileType.BOMB || tile2.type == TileType.ENEMY)) {
            this.list[ResolveType.MOVE_BLOCK].resolve(tile1, tile2);
          } else if (tile1.type == TileType.PLAYER && tile2.type == TileType.BOMB) {
            this.list[ResolveType.PLAYER_BOMB].resolve(tile1, tile2);
          } else if (tile1.type == TileType.FLAME) {
            this.list[ResolveType.FLAME_TILE].resolve(tile1, tile2);
          }
        }
        // resolve(tile1:Tile, tile2:Tile){
        //     if((tile1.type == TileType.PLAYER && tile2.type == TileType.STATIC) || 
        //         tile1.type == TileType.STATIC && tile2.type == TileType.PLAYER){
        //             let a:Tile, b:Tile;
        //             if(tile1.type == TileType.PLAYER){
        //                 a = tile1;
        //                 b = tile2;
        //             }else{
        //                 a = tile2;
        //                 b = tile1;
        //             }
        //             this.list[ResolveType.PLAYER_STATIC].resolve(a, b);
        //     }        
        // }
        ;

        _createClass(Resolver, null, [{
          key: "instance",
          get: function get() {
            if (!Resolver._instance) {
              Resolver._instance = new Resolver();
            }
            return Resolver._instance;
          }
        }]);
        return Resolver;
      }());
      Resolver._instance = null;
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/ResourceManager.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './EventManager.ts', './GlobalData.ts'], function (exports) {
  var _createClass, cclegacy, assetManager, log, EventManager, BundleType;
  return {
    setters: [function (module) {
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
      assetManager = module.assetManager;
      log = module.log;
    }, function (module) {
      EventManager = module.EventManager;
    }, function (module) {
      BundleType = module.BundleType;
    }],
    execute: function () {
      cclegacy._RF.push({}, "76bf4sWu69H/5IpQvy438iw", "ResourceManager", undefined);
      var ResourceManager = exports('ResourceManager', /*#__PURE__*/function () {
        function ResourceManager() {
          this._batchs = new Map();
          this._bundles = [];
          this._bundleCount = 0;
          this.bundleEvent = {};
        }
        var _proto = ResourceManager.prototype;
        //---------------bundle----------------------------------
        _proto.bundleLoadAsset = function bundleLoadAsset(path, bundleName, type, callback) {
          var bundle = assetManager.getBundle(bundleName);
          bundle.load(path, type, callback);
        };
        _proto.addBundles = function addBundles(name) {
          var bundle = assetManager.getBundle(name);
          if (bundle == null) {
            this._bundles.push(name);
          }
        };
        _proto.loadBundles = function loadBundles(event, target) {
          if (event === void 0) {
            event = "";
          }
          if (target === void 0) {
            target = EventManager.instance;
          }
          if (event) {
            this.bundleEvent["event"] = event;
            this.bundleEvent["target"] = target;
          }
          while (this._bundles.length > 0) {
            var name = this._bundles.pop();
            ++this._bundleCount;
            assetManager.loadBundle(name, this._onBundleLoaded.bind(this));
          }
        };
        _proto._onBundleLoaded = function _onBundleLoaded(err, bundle) {
          if (err) {
            log(err.message);
          }
          --this._bundleCount;
          if (this._bundleCount == 0) {
            if (this.bundleEvent["event"]) {
              this.bundleEvent["target"].emit(this.bundleEvent["event"]);
              delete this.bundleEvent["event"];
            }
          }
        }
        //----------------asset------------------------------
        ;

        _proto.createNewBatch = function createNewBatch(name, event, target) {
          if (event === void 0) {
            event = "";
          }
          if (target === void 0) {
            target = null;
          }
          if (this._batchs.has(name)) {
            this.removeBatch(name);
          }
          var batch = new BatchData(name);
          batch.parent = this;
          batch.event = event;
          batch.target = target;
          this._batchs.set(name, batch);
          return batch;
        };
        _proto.getBatch = function getBatch(name) {
          return this._batchs.get(name);
        };
        _proto.removeBatch = function removeBatch(name) {
          this._batchs["delete"](name);
        };
        _proto.getAsset = function getAsset(path, bundleName, assetType) {
          if (bundleName === void 0) {
            bundleName = "resources";
          }
          if (assetType === void 0) {
            assetType = null;
          }
          var bundle = assetManager.getBundle(bundleName);
          if (bundle == null) {
            log("bundle is not exist");
            return null;
          }
          return bundle.get(path, assetType);
        };
        _proto.releaseAsset = function releaseAsset(path, bundleName, assetType) {
          if (bundleName === void 0) {
            bundleName = "resources";
          }
          if (assetType === void 0) {
            assetType = null;
          }
          var bundle = assetManager.getBundle(bundleName);
          if (bundle == null) {
            log("bundle is not exist");
            return null;
          }
          bundle.release(path, assetType);
        };
        _proto.directLoad = function directLoad(bundleName, path, isDir, assettype, callback) {
          if (isDir === void 0) {
            isDir = false;
          }
          if (!isDir) {
            assetManager.getBundle(bundleName).load(path, assettype, callback);
          } else {
            assetManager.getBundle(bundleName).loadDir(path, assettype, callback);
          }
        };
        _createClass(ResourceManager, null, [{
          key: "instance",
          get: function get() {
            if (!ResourceManager._instance) {
              ResourceManager._instance = new ResourceManager();
            }
            return ResourceManager._instance;
          }
        }]);
        return ResourceManager;
      }());
      ResourceManager._instance = null;
      var BatchData = /*#__PURE__*/function () {
        function BatchData(name) {
          this.name = "";
          this._list = [];
          this._total = 0;
          this._isStart = false;
          this.event = "";
          this.target = null;
          this.parent = null;
          this.paths = [];
          this.name = name;
        }
        var _proto2 = BatchData.prototype;
        _proto2.addResource = function addResource(path, bundleName, type, assetType, event, target, args) {
          if (event === void 0) {
            event = "";
          }
          if (target === void 0) {
            target = null;
          }
          if (args === void 0) {
            args = [];
          }
          if (this.paths.includes(path)) {
            return;
          }
          this.paths.push(path);
          var data = new ItemData(path, bundleName, type, assetType, event, target, args);
          this._list.push(data);
          ++this._total;
        };
        _proto2.start = function start() {
          if (this._list.length > 0) {
            this._isStart = true;
            this._process();
          } else {
            this._isStart = false;
            if (this.event) {
              this.target.emit(this.event);
            }
            this.parent.removeBatch(this.name);
          }
        };
        _proto2._process = function _process() {
          if (!this._isStart) {
            return;
          }
          while (this._list.length > 0) {
            var item = this._list.pop();
            if (item.type == BundleType.Asset) {
              if (item.args && item.args[0] == "dir") {
                if (item.args[1] == "preload") {
                  assetManager.getBundle(item.bundle).preloadDir(item.path, item.assetType, this._onAssetPreloaded.bind(this, item.event, item.target, item.args));
                } else {
                  assetManager.getBundle(item.bundle).loadDir(item.path, item.assetType, this._onAssetLoaded.bind(this, item.event, item.target, item.args));
                }
              } else {
                if (item.args[1] == "preload") {
                  assetManager.getBundle(item.bundle).preload(item.path, item.assetType, this._onAssetPreloaded.bind(this, item.event, item.target, item.args));
                } else {
                  assetManager.getBundle(item.bundle).load(item.path, item.assetType, this._onAssetLoaded.bind(this, item.event, item.target, item.args));
                }
              }
            } else if (item.type == BundleType.Scence) {
              if (item.args[1] == "preload") {
                assetManager.getBundle(item.bundle).preloadScene(item.path, this._onAssetPreloaded.bind(this, item.event, item.target, item.args));
              } else {
                assetManager.getBundle(item.bundle).loadScene(item.path, this._onAssetLoaded.bind(this, item.event, item.target, item.args));
              }
            }
          }
        };
        _proto2._checkLoadCompleted = function _checkLoadCompleted() {
          this._total -= 1;
          if (this._total == 0) {
            this._isStart = false;
            if (this.event) {
              this.target.emit(this.event);
            }
            ResourceManager.instance.removeBatch(this.name);
          }
        };
        _proto2._onAssetLoaded = function _onAssetLoaded(event, target, args, err, asset) {
          if (err) {
            log(err.message);
          }
          if (event) {
            target.emit(event, asset, args);
          }
          this._checkLoadCompleted();
        };
        _proto2._onAssetPreloaded = function _onAssetPreloaded(event, target, args, err, asset) {
          if (err) {
            log(err.message);
          }
          if (event) {
            target.emit(event, asset, args);
          }
          this._checkLoadCompleted();
        };
        return BatchData;
      }();
      var ItemData = function ItemData(path, bundle, type, assetType, event, target, args) {
        this.path = "";
        this.bundle = "";
        this.type = null;
        this.assetType = null;
        this.event = null;
        this.target = null;
        this.args = [];
        this.path = path;
        this.bundle = bundle;
        this.type = type;
        this.assetType = assetType;
        this.event = event;
        this.target = target;
        this.args = args;
      };
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/ResovleFlameTile.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './ResolveBase.ts'], function (exports) {
  var _inheritsLoose, cclegacy, ResolveBase;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      ResolveBase = module.ResolveBase;
    }],
    execute: function () {
      cclegacy._RF.push({}, "35194F8Jd1NSJgI5uiIUSNN", "ResovleFlameTile", undefined);
      var ResovleFlameTile = exports('ResovleFlameTile', /*#__PURE__*/function (_ResolveBase) {
        _inheritsLoose(ResovleFlameTile, _ResolveBase);
        function ResovleFlameTile() {
          return _ResolveBase.call(this) || this;
        }
        var _proto = ResovleFlameTile.prototype;
        _proto.resolve = function resolve(flame, tile) {
          if (tile.canFlameHit) {
            tile.flameHit(flame);
          }
        };
        return ResovleFlameTile;
      }(ResolveBase));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/ResovlePlayerMove.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './GlobalData.ts', './MapManager.ts', './ResolveBase.ts'], function (exports) {
  var _inheritsLoose, _createForOfIteratorHelperLoose, cclegacy, GlobalData, TileType, MapManager, ResolveBase;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
      _createForOfIteratorHelperLoose = module.createForOfIteratorHelperLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      GlobalData = module.GlobalData;
      TileType = module.TileType;
    }, function (module) {
      MapManager = module.MapManager;
    }, function (module) {
      ResolveBase = module.ResolveBase;
    }],
    execute: function () {
      cclegacy._RF.push({}, "ce62ay3oVNJgIDhcJw+P6My", "ResovlePlayerMove", undefined);
      var ResovlePlayerMove = exports('ResovlePlayerMove', /*#__PURE__*/function (_ResolveBase) {
        _inheritsLoose(ResovlePlayerMove, _ResolveBase);
        function ResovlePlayerMove() {
          var _this;
          _this = _ResolveBase.call(this) || this;
          _this.blockSlideTypes = [TileType.STATIC, TileType.BOMB];
          return _this;
        }
        var _proto = ResovlePlayerMove.prototype;
        _proto.resolve = function resolve(player, moveTile) {
          moveTile.moveDir.set(0, 0);
          moveTile.slideDir.set(0, 0);
          this.checkRight(player, moveTile);
          this.checkLeft(player, moveTile);
          this.checkUp(player, moveTile);
          this.checkDown(player, moveTile);
        };
        _proto.checkRight = function checkRight(player, moveTile) {
          if (player.realDir.x != 1) {
            return;
          }
          if (player.collideRect.intersects(moveTile.collideRect)) {
            var isSlide = false;
            var rightDown = MapManager.instance.getTiles(player.minRow, player.maxCol);
            if (player.collideRect.yMax - moveTile.collideRect.yMin < GlobalData.TILE_HEIGHT * 0.5 && !this.blockToSlide(rightDown, this.blockSlideTypes)) {
              player.slideDir.y = -1;
              isSlide = true;
            }
            var rightUp = MapManager.instance.getTiles(player.maxRow, player.maxCol);
            if (moveTile.collideRect.yMax - player.collideRect.yMin < GlobalData.TILE_HEIGHT * 0.5 && !this.blockToSlide(rightUp, this.blockSlideTypes)) {
              player.slideDir.y = 1;
              isSlide = true;
            }
            if (isSlide) {
              var dx = moveTile.collideRect.xMin - player.collideRect.xMax;
              player.node.x = player.node.x + dx - 1;
            } else {
              this.moveRight(player, moveTile);
            }
          }
        };
        _proto.checkLeft = function checkLeft(player, moveTile) {
          if (player.realDir.x != -1) {
            return;
          }
          if (player.collideRect.intersects(moveTile.collideRect)) {
            var isSlide = false;
            var leftDown = MapManager.instance.getTiles(player.minRow, player.minCol);
            if (player.collideRect.yMax - moveTile.collideRect.yMin < GlobalData.TILE_HEIGHT * 0.5 && !this.blockToSlide(leftDown, this.blockSlideTypes)) {
              player.slideDir.y = -1;
              isSlide = true;
            }
            var leftUp = MapManager.instance.getTiles(player.maxRow, player.minCol);
            if (moveTile.collideRect.yMax - player.collideRect.yMin < GlobalData.TILE_HEIGHT * 0.5 && !this.blockToSlide(leftUp, this.blockSlideTypes)) {
              player.slideDir.y = 1;
              isSlide = true;
            }
            if (isSlide) {
              var dx = moveTile.collideRect.xMax - player.collideRect.xMin;
              player.node.x = player.node.x + dx + 1;
            } else {
              this.moveLeft(player, moveTile);
            }
          }
        };
        _proto.checkUp = function checkUp(player, moveTile) {
          if (player.realDir.y != 1) {
            return;
          }
          if (player.collideRect.intersects(moveTile.collideRect)) {
            var isSlide = false;
            var leftUp = MapManager.instance.getTiles(player.maxRow, player.minCol);
            if (player.collideRect.xMax - moveTile.collideRect.xMin < GlobalData.TILE_WIDTH * 0.5 && !this.blockToSlide(leftUp, this.blockSlideTypes)) {
              player.slideDir.x = -1;
              isSlide = true;
            }
            var rightUp = MapManager.instance.getTiles(player.maxRow, player.maxCol);
            if (moveTile.collideRect.xMax - player.collideRect.xMin < GlobalData.TILE_WIDTH * 0.5 && !this.blockToSlide(rightUp, this.blockSlideTypes)) {
              player.slideDir.x = 1;
              isSlide = true;
            }
            if (isSlide) {
              var dy = moveTile.collideRect.yMin - player.collideRect.yMax;
              player.node.y = player.node.y + dy - 1;
            } else {
              this.moveUp(player, moveTile);
            }
          }
        };
        _proto.checkDown = function checkDown(player, moveTile) {
          if (player.realDir.y != -1) {
            return;
          }
          if (player.collideRect.intersects(moveTile.collideRect)) {
            var isSlide = false;
            var leftDown = MapManager.instance.getTiles(player.minRow, player.minCol);
            if (player.collideRect.xMax - moveTile.collideRect.xMin < GlobalData.TILE_WIDTH * 0.5 && !this.blockToSlide(leftDown, this.blockSlideTypes)) {
              player.slideDir.x = -1;
              isSlide = true;
            }
            var rightDown = MapManager.instance.getTiles(player.minRow, player.maxCol);
            if (moveTile.collideRect.xMax - player.collideRect.xMin < GlobalData.TILE_WIDTH * 0.5 && !this.blockToSlide(rightDown, this.blockSlideTypes)) {
              player.slideDir.x = 1;
              isSlide = true;
            }
            if (isSlide) {
              var dy = moveTile.collideRect.yMax - player.collideRect.yMin;
              player.node.y = player.node.y + dy + 1;
            } else {
              this.moveDown(player, moveTile);
            }
          }
        };
        _proto.moveRight = function moveRight(player, moveTile) {
          var dx = player.collideRect.xMax - moveTile.collideRect.xMin + 1;
          moveTile.node.x = moveTile.node.x + dx;
          moveTile.moveDir.x = 1;
          var isMove = moveTile.checkMoveRight();
          if (isMove) {
            player.node.x = player.node.x - (player.collideRect.xMax - moveTile.collideRect.xMin) - 1;
          }
        };
        _proto.moveLeft = function moveLeft(player, moveTile) {
          var dx = moveTile.collideRect.xMax - player.collideRect.xMin + 1; //注意这里的+1就是下面的-1
          moveTile.node.x = moveTile.node.x - dx;
          moveTile.moveDir.x = -1;
          var isMove = moveTile.checkMoveLeft();
          if (isMove) {
            player.node.x = player.node.x + (moveTile.collideRect.xMax - player.collideRect.xMin) + 1;
          }
        };
        _proto.moveUp = function moveUp(player, moveTile) {
          var dy = player.collideRect.yMax - moveTile.collideRect.yMin + 1;
          moveTile.node.y = moveTile.node.y + dy;
          moveTile.moveDir.y = 1;
          var isMove = moveTile.checkMoveUp();
          if (isMove) {
            player.node.y = player.node.y - (player.collideRect.yMax - moveTile.collideRect.yMin) - 1;
          }
        };
        _proto.moveDown = function moveDown(player, moveTile) {
          var dy = moveTile.collideRect.yMax - player.collideRect.yMin + 1; //注意这里的+1和下面的-1是样的。
          moveTile.node.y = moveTile.node.y - dy;
          moveTile.moveDir.y = -1;
          var isMove = moveTile.checkMoveDown();
          if (isMove) {
            player.node.y = player.node.y + (moveTile.collideRect.yMax - player.collideRect.yMin) + 1;
          }
        };
        _proto.blockToSlide = function blockToSlide(tiles, types) {
          for (var _iterator = _createForOfIteratorHelperLoose(types), _step; !(_step = _iterator()).done;) {
            var type = _step.value;
            if (MapManager.instance.hasType(tiles, type)) {
              return true;
            }
          }
          return false;
        };
        return ResovlePlayerMove;
      }(ResolveBase));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/StateBase.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc'], function (exports) {
  var _inheritsLoose, cclegacy, _decorator, Component;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Component = module.Component;
    }],
    execute: function () {
      var _dec, _class;
      cclegacy._RF.push({}, "b041bQ0wFZPkZJgZh3G6MR1", "StateBase", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var StateBase = exports('StateBase', (_dec = ccclass('StateBase'), _dec(_class = /*#__PURE__*/function (_Component) {
        _inheritsLoose(StateBase, _Component);
        function StateBase() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Component.call.apply(_Component, [this].concat(args)) || this;
          _this.stateMachine = void 0;
          return _this;
        }
        var _proto = StateBase.prototype;
        // parentState:StateBase;
        _proto.start = function start() {
          // let p = this.node.getParent();
          // if(p.getComponent(StateBase)){
          //     this.parentState = p.getComponent(StateBase);
          // }
        };
        _proto.enter = function enter() {};
        _proto.exit = function exit() {};
        _proto.updateData = function updateData(dt) {};
        return StateBase;
      }(Component)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/StateBomb200Explode.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './StateBase.ts', './FlameCreator.ts'], function (exports) {
  var _inheritsLoose, cclegacy, _decorator, StateBase, FlameCreator;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
    }, function (module) {
      StateBase = module.StateBase;
    }, function (module) {
      FlameCreator = module.FlameCreator;
    }],
    execute: function () {
      var _dec, _class;
      cclegacy._RF.push({}, "32177ydoO5At4p/Gpj7y/i6", "StateBomb200Explode", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var StateBomb200Explode = exports('StateBomb200Explode', (_dec = ccclass('StateBomb200Explode'), _dec(_class = /*#__PURE__*/function (_StateBase) {
        _inheritsLoose(StateBomb200Explode, _StateBase);
        function StateBomb200Explode() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _StateBase.call.apply(_StateBase, [this].concat(args)) || this;
          _this.bomb = void 0;
          return _this;
        }
        var _proto = StateBomb200Explode.prototype;
        _proto.onLoad = function onLoad() {
          this.bomb = this.stateMachine.host;
        };
        _proto.enter = function enter() {
          FlameCreator.instance.create(this.bomb);
          this.bomb.destroySelf();
        };
        _proto.exit = function exit() {};
        _proto.updateData = function updateData(dt) {};
        return StateBomb200Explode;
      }(StateBase)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/StateBomb200Idle.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './GlobalData.ts', './StateBase.ts', './MapManager.ts', './Resolver.ts'], function (exports) {
  var _inheritsLoose, cclegacy, _decorator, TileType, StateBase, MapManager, Resolver;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
    }, function (module) {
      TileType = module.TileType;
    }, function (module) {
      StateBase = module.StateBase;
    }, function (module) {
      MapManager = module.MapManager;
    }, function (module) {
      Resolver = module.Resolver;
    }],
    execute: function () {
      var _dec, _class;
      cclegacy._RF.push({}, "4657dIDJAJP2pvgwmNg3UYd", "StateBomb200Idle", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var StateBomb200Idle = exports('StateBomb200Idle', (_dec = ccclass('StateBomb200Idle'), _dec(_class = /*#__PURE__*/function (_StateBase) {
        _inheritsLoose(StateBomb200Idle, _StateBase);
        function StateBomb200Idle() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _StateBase.call.apply(_StateBase, [this].concat(args)) || this;
          _this.bomb = void 0;
          return _this;
        }
        var _proto = StateBomb200Idle.prototype;
        _proto.onLoad = function onLoad() {
          this.bomb = this.stateMachine.host;
        };
        _proto.enter = function enter() {
          var _this2 = this;
          this.bomb.animation.play("bomb_idle");
          this.bomb.scheduleOnce(function () {
            _this2.bomb.explode();
          }, 3);
          var tiles = MapManager.instance.getTiles(this.bomb.minRow, this.bomb.minCol);
          tiles.forEach(function (tile) {
            if (tile.type == TileType.FLAME) {
              Resolver.instance.resolve(tile, _this2.bomb);
            }
          });
        };
        _proto.exit = function exit() {};
        _proto.updateData = function updateData(dt) {};
        return StateBomb200Idle;
      }(StateBase)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/StateMachine.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './StateBase.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, _createForOfIteratorHelperLoose, cclegacy, _decorator, Node, CCString, log, Component, StateBase;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
      _createForOfIteratorHelperLoose = module.createForOfIteratorHelperLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Node = module.Node;
      CCString = module.CCString;
      log = module.log;
      Component = module.Component;
    }, function (module) {
      StateBase = module.StateBase;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _class, _class2, _descriptor, _descriptor2;
      cclegacy._RF.push({}, "20ad9w4b3dMHaHgaPHKlOt8", "StateMachine", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var StateMachine = exports('StateMachine', (_dec = ccclass('StateMachine'), _dec2 = property(Node), _dec3 = property(CCString), _dec(_class = (_class2 = /*#__PURE__*/function (_Component) {
        _inheritsLoose(StateMachine, _Component);
        function StateMachine() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Component.call.apply(_Component, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "hostNode", _descriptor, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "scriptName", _descriptor2, _assertThisInitialized(_this));
          _this.host = void 0;
          _this.states = new Map();
          _this._current = void 0;
          _this._previous = void 0;
          return _this;
        }
        var _proto = StateMachine.prototype;
        _proto.onLoad = function onLoad() {
          if (!this.scriptName) {
            this.scriptName = this.hostNode.name;
          }
          this.host = this.hostNode.getComponent(this.scriptName);
          for (var _iterator = _createForOfIteratorHelperLoose(this.node.children), _step; !(_step = _iterator()).done;) {
            var child = _step.value;
            this.states[child.name] = child.getComponent(StateBase);
            this.states[child.name].stateMachine = this;
          }
        };
        _proto.setStateByName = function setStateByName(stateName, force) {
          if (force === void 0) {
            force = false;
          }
          var state = this.states[stateName];
          this.setState(state, force);
        };
        _proto.setState = function setState(state, force) {
          if (force === void 0) {
            force = false;
          }
          if (!force && state == this._current) {
            return;
          }
          if (this._current) {
            this._current.exit();
          }
          this._previous = this._current;
          this._current = state;
          try {
            this._current.enter();
          } catch (error) {
            log(error);
          }
        };
        _proto.getCurrentName = function getCurrentName() {
          return this._current.name;
        };
        _proto.updateData = function updateData(dt) {
          if (dt === void 0) {
            dt = 0;
          }
          if (this._current) {
            this._current.updateData(dt);
          }
        };
        return StateMachine;
      }(Component), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "hostNode", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "scriptName", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return "";
        }
      })), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/StatePlayer100Idle.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './StateBase.ts'], function (exports) {
  var _inheritsLoose, cclegacy, _decorator, StateBase;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
    }, function (module) {
      StateBase = module.StateBase;
    }],
    execute: function () {
      var _dec, _class;
      cclegacy._RF.push({}, "c50157kbOJGIZ8GAgiV8YZL", "StatePlayer100Idle", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var StatePlayer100Idle = exports('StatePlayer100Idle', (_dec = ccclass('StatePlayer100Idle'), _dec(_class = /*#__PURE__*/function (_StateBase) {
        _inheritsLoose(StatePlayer100Idle, _StateBase);
        function StatePlayer100Idle() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _StateBase.call.apply(_StateBase, [this].concat(args)) || this;
          _this.player = void 0;
          return _this;
        }
        var _proto = StatePlayer100Idle.prototype;
        _proto.onLoad = function onLoad() {
          this.player = this.stateMachine.host;
        };
        _proto.enter = function enter() {
          this.player.animation.play("player_idle");
        };
        _proto.exit = function exit() {};
        _proto.checkMove = function checkMove() {
          if (!this.player.dir.equals2f(0, 0)) {
            this.stateMachine.setStateByName("StatePlayer100Move");
          }
        };
        _proto.updateData = function updateData(dt) {
          this.checkMove();
        };
        return StatePlayer100Idle;
      }(StateBase)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/StatePlayer100Move.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './StateBase.ts', './MapManager.ts', './GlobalData.ts', './Resolver.ts'], function (exports) {
  var _inheritsLoose, cclegacy, _decorator, Vec2, StateBase, MapManager, TileType, Resolver;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Vec2 = module.Vec2;
    }, function (module) {
      StateBase = module.StateBase;
    }, function (module) {
      MapManager = module.MapManager;
    }, function (module) {
      TileType = module.TileType;
    }, function (module) {
      Resolver = module.Resolver;
    }],
    execute: function () {
      var _dec, _class;
      cclegacy._RF.push({}, "dae4dqswQZPjZBjHAHEhMHt", "StatePlayer100Move", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var StatePlayer100Move = exports('StatePlayer100Move', (_dec = ccclass('StatePlayer100Move'), _dec(_class = /*#__PURE__*/function (_StateBase) {
        _inheritsLoose(StatePlayer100Move, _StateBase);
        function StatePlayer100Move() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _StateBase.call.apply(_StateBase, [this].concat(args)) || this;
          _this.player = void 0;
          _this.preDir = new Vec2();
          return _this;
        }
        var _proto = StatePlayer100Move.prototype;
        _proto.onLoad = function onLoad() {
          this.player = this.stateMachine.host;
        };
        _proto.enter = function enter() {
          this.setAnimation();
          // this.move();
        };

        _proto.exit = function exit() {};
        _proto.updateData = function updateData(dt) {
          this.checkMove();
        };
        _proto.setAnimation = function setAnimation() {
          if (this.player.dir.x == 1) {
            this.player.playerAnimation("player_right");
          } else if (this.player.dir.x == -1) {
            this.player.playerAnimation("player_left");
          } else if (this.player.dir.y == 1) {
            this.player.playerAnimation("player_up");
          } else if (this.player.dir.y == -1) {
            this.player.playerAnimation("player_down");
          }
        };
        _proto.move = function move() {
          //移动前
          this.player.slideDir.set(0, 0);
          this.player.prePos.set(this.player.node.x, this.player.node.y);
          //应该是往那边移动就处理那边的角
          if (this.player.dir.x == 1) {
            this.player.realDir.set(1, 0);
            this.player.node.x += this.player.dir.x * 3;
            this.checkMoveRight();
          } else if (this.player.dir.x == -1) {
            this.player.realDir.set(-1, 0);
            this.player.node.x += this.player.dir.x * 3;
            this.checkMoveLeft();
          } else if (this.player.dir.y == 1) {
            this.player.realDir.set(0, 1);
            this.player.node.y += this.player.dir.y * 3;
            this.checkMoveUp();
          } else if (this.player.dir.y == -1) {
            this.player.realDir.set(0, -1);
            this.player.node.y += this.player.dir.y * 3;
            this.checkMoveDown();
          }
          //移动后，检测完之后需要的移动
          this.slide();
          this.player.updateMapPos();
        };
        _proto.checkMoveRight = function checkMoveRight() {
          var _this2 = this;
          var rightDown = MapManager.instance.getTiles(this.player.minRow, this.player.maxCol);
          var rightUp = MapManager.instance.getTiles(this.player.maxRow, this.player.maxCol);
          var staticTiles = [];
          var otherTiels = [];
          rightUp.forEach(function (tile) {
            if (tile == _this2.player) {
              return;
            }
            if (tile.type == TileType.STATIC) {
              staticTiles.push(tile);
            } else {
              otherTiels.push(tile);
            }
          });
          rightDown.forEach(function (tile) {
            if (tile == _this2.player) {
              return;
            }
            if (tile.type == TileType.STATIC) {
              staticTiles.push(tile);
            } else {
              otherTiels.push(tile);
            }
          });
          var tiles = staticTiles.concat(otherTiels);
          tiles.forEach(function (tile) {
            if (tile.type == TileType.FLAME) {
              Resolver.instance.resolve(tile, _this2.player);
            } else {
              Resolver.instance.resolve(_this2.player, tile);
            }
          });
        };
        _proto.checkMoveLeft = function checkMoveLeft() {
          var _this3 = this;
          var leftDown = MapManager.instance.getTiles(this.player.minRow, this.player.minCol);
          var leftUp = MapManager.instance.getTiles(this.player.maxRow, this.player.minCol);
          var staticTiles = [];
          var otherTiels = [];
          leftUp.forEach(function (tile) {
            if (tile == _this3.player) {
              return;
            }
            if (tile.type == TileType.STATIC) {
              staticTiles.push(tile);
            } else {
              otherTiels.push(tile);
            }
          });
          leftDown.forEach(function (tile) {
            if (tile == _this3.player) {
              return;
            }
            if (tile.type == TileType.STATIC) {
              staticTiles.push(tile);
            } else {
              otherTiels.push(tile);
            }
          });
          var tiles = staticTiles.concat(otherTiels);
          tiles.forEach(function (tile) {
            if (tile.type == TileType.FLAME) {
              Resolver.instance.resolve(tile, _this3.player);
            } else {
              Resolver.instance.resolve(_this3.player, tile);
            }
          });
        };
        _proto.checkMoveUp = function checkMoveUp() {
          var _this4 = this;
          var leftUp = MapManager.instance.getTiles(this.player.maxRow, this.player.minCol);
          var rightUp = MapManager.instance.getTiles(this.player.maxRow, this.player.maxCol);
          var staticTiles = [];
          var otherTiels = [];
          rightUp.forEach(function (tile) {
            if (tile == _this4.player) {
              return;
            }
            if (tile.type == TileType.STATIC) {
              staticTiles.push(tile);
            } else {
              otherTiels.push(tile);
            }
          });
          leftUp.forEach(function (tile) {
            if (tile == _this4.player) {
              return;
            }
            if (tile.type == TileType.STATIC) {
              staticTiles.push(tile);
            } else {
              otherTiels.push(tile);
            }
          });
          var tiles = staticTiles.concat(otherTiels);
          tiles.forEach(function (tile) {
            if (tile.type == TileType.FLAME) {
              Resolver.instance.resolve(tile, _this4.player);
            } else {
              Resolver.instance.resolve(_this4.player, tile);
            }
          });
        };
        _proto.checkMoveDown = function checkMoveDown() {
          var _this5 = this;
          var leftDown = MapManager.instance.getTiles(this.player.minRow, this.player.minCol);
          var rightDown = MapManager.instance.getTiles(this.player.minRow, this.player.maxCol);
          var staticTiles = [];
          var otherTiels = [];
          leftDown.forEach(function (tile) {
            if (tile == _this5.player) {
              return;
            }
            if (tile.type == TileType.STATIC) {
              staticTiles.push(tile);
            } else {
              otherTiels.push(tile);
            }
          });
          rightDown.forEach(function (tile) {
            if (tile == _this5.player) {
              return;
            }
            if (tile.type == TileType.STATIC) {
              staticTiles.push(tile);
            } else {
              otherTiels.push(tile);
            }
          });
          var tiles = staticTiles.concat(otherTiels);
          tiles.forEach(function (tile) {
            if (tile.type == TileType.FLAME) {
              Resolver.instance.resolve(tile, _this5.player);
            } else {
              Resolver.instance.resolve(_this5.player, tile);
            }
          });
        };
        _proto.slide = function slide() {
          if (this.player.slideDir.y != 0 || this.player.slideDir.x != 0) {
            this.player.prePos.set(this.player.node.x, this.player.node.y);
            this.player.node.y += this.player.slideDir.y;
            this.player.node.x += this.player.slideDir.x;
            if (this.player.slideDir.y > 0) {
              this.player.realDir.set(0, 1);
              this.checkMoveUp();
            } else if (this.player.slideDir.y < 0) {
              this.player.realDir.set(0, -1);
              this.checkMoveDown();
            }
            if (this.player.slideDir.x > 0) {
              this.player.realDir.set(1, 0);
              this.checkMoveRight();
            } else if (this.player.slideDir.x < 0) {
              this.player.realDir.set(-1, 0);
              this.checkMoveLeft();
            }
          }
        };
        _proto.checkMove = function checkMove() {
          if (this.player.dir.equals2f(0, 0)) {
            this.stateMachine.setStateByName("StatePlayer100Idle");
          } else {
            //改变animation就可以了
            this.setAnimation();
            this.move();
            // if(this.player.dir.x != 0){//先左右、后上下
            //     if(this.preDir.x != this.player.dir.x){
            //         this.stateMachine.setStateByName("StatePlayer100Move", true);
            //     }
            // }else{
            //     if(this.preDir.y != this.player.dir.y){
            //         this.stateMachine.setStateByName("StatePlayer100Move", true);
            //     }
            // }
          }
        };

        return StatePlayer100Move;
      }(StateBase)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/StatePlayer101Idle.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './StateBase.ts'], function (exports) {
  var _inheritsLoose, cclegacy, _decorator, StateBase;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
    }, function (module) {
      StateBase = module.StateBase;
    }],
    execute: function () {
      var _dec, _class;
      cclegacy._RF.push({}, "66c28w3b1JCtq3DhhKxyDkF", "StatePlayer101Idle", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var StatePlayer101Idle = exports('StatePlayer101Idle', (_dec = ccclass('StatePlayer101Idle'), _dec(_class = /*#__PURE__*/function (_StateBase) {
        _inheritsLoose(StatePlayer101Idle, _StateBase);
        function StatePlayer101Idle() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _StateBase.call.apply(_StateBase, [this].concat(args)) || this;
          _this.player = void 0;
          return _this;
        }
        var _proto = StatePlayer101Idle.prototype;
        _proto.onLoad = function onLoad() {
          this.player = this.stateMachine.host;
        };
        _proto.enter = function enter() {
          if (this.player.faceTo.x == 1) {
            this.player.playAnimation("idle_r");
          } else if (this.player.faceTo.x == -1) {
            this.player.playAnimation("idle_l");
          } else if (this.player.faceTo.y == 1) {
            this.player.playAnimation("idle_b");
          } else if (this.player.faceTo.y == -1) {
            this.player.playAnimation("idle_f");
          }
        };
        _proto.exit = function exit() {};
        _proto.checkMove = function checkMove() {
          if (!this.player.dir.equals2f(0, 0)) {
            this.stateMachine.setStateByName("StatePlayer101Move");
          }
        };
        _proto.updateData = function updateData(dt) {
          this.checkMove();
        };
        return StatePlayer101Idle;
      }(StateBase)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/StatePlayer101Move.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './StateBase.ts', './MapManager.ts', './GlobalData.ts', './Resolver.ts'], function (exports) {
  var _inheritsLoose, cclegacy, _decorator, Vec2, StateBase, MapManager, TileType, Resolver;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Vec2 = module.Vec2;
    }, function (module) {
      StateBase = module.StateBase;
    }, function (module) {
      MapManager = module.MapManager;
    }, function (module) {
      TileType = module.TileType;
    }, function (module) {
      Resolver = module.Resolver;
    }],
    execute: function () {
      var _dec, _class;
      cclegacy._RF.push({}, "a8bb9FOQFtNSofZ+2OMIyss", "StatePlayer101Move", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var StatePlayer101Move = exports('StatePlayer101Move', (_dec = ccclass('StatePlayer101Move'), _dec(_class = /*#__PURE__*/function (_StateBase) {
        _inheritsLoose(StatePlayer101Move, _StateBase);
        function StatePlayer101Move() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _StateBase.call.apply(_StateBase, [this].concat(args)) || this;
          _this.player = void 0;
          _this.preDir = new Vec2();
          return _this;
        }
        var _proto = StatePlayer101Move.prototype;
        _proto.onLoad = function onLoad() {
          this.player = this.stateMachine.host;
        };
        _proto.enter = function enter() {
          this.setAnimation();
          // this.move();
        };

        _proto.exit = function exit() {};
        _proto.updateData = function updateData(dt) {
          this.checkMove();
        };
        _proto.setAnimation = function setAnimation() {
          this.player.faceTo.set(0, 0);
          if (this.player.dir.x == 1) {
            this.player.faceTo.set(1, 0);
            this.player.playAnimation("walk_r");
          } else if (this.player.dir.x == -1) {
            this.player.faceTo.set(-1, 0);
            this.player.playAnimation("walk_l");
          } else if (this.player.dir.y == 1) {
            this.player.faceTo.set(0, 1);
            this.player.playAnimation("walk_b");
          } else if (this.player.dir.y == -1) {
            this.player.faceTo.set(0, -1);
            this.player.playAnimation("walk_f");
          }
        };
        _proto.move = function move() {
          //移动前
          this.player.slideDir.set(0, 0);
          this.player.prePos.set(this.player.node.x, this.player.node.y);
          //应该是往那边移动就处理那边的角
          if (this.player.dir.x == 1) {
            this.player.realDir.set(1, 0);
            this.player.node.x += this.player.dir.x * 3;
            this.checkMoveRight();
          } else if (this.player.dir.x == -1) {
            this.player.realDir.set(-1, 0);
            this.player.node.x += this.player.dir.x * 3;
            this.checkMoveLeft();
          } else if (this.player.dir.y == 1) {
            this.player.realDir.set(0, 1);
            this.player.node.y += this.player.dir.y * 3;
            this.checkMoveUp();
          } else if (this.player.dir.y == -1) {
            this.player.realDir.set(0, -1);
            this.player.node.y += this.player.dir.y * 3;
            this.checkMoveDown();
          }
          //移动后，检测完之后需要的移动
          this.slide();
          this.player.updateMapPos();
        };
        _proto.checkMoveRight = function checkMoveRight() {
          var _this2 = this;
          var rightDown = MapManager.instance.getTiles(this.player.minRow, this.player.maxCol);
          var rightUp = MapManager.instance.getTiles(this.player.maxRow, this.player.maxCol);
          var staticTiles = [];
          var otherTiels = [];
          rightUp.forEach(function (tile) {
            if (tile == _this2.player) {
              return;
            }
            if (tile.type == TileType.STATIC) {
              staticTiles.push(tile);
            } else {
              otherTiels.push(tile);
            }
          });
          rightDown.forEach(function (tile) {
            if (tile == _this2.player) {
              return;
            }
            if (tile.type == TileType.STATIC) {
              staticTiles.push(tile);
            } else {
              otherTiels.push(tile);
            }
          });
          var tiles = staticTiles.concat(otherTiels);
          tiles.forEach(function (tile) {
            if (tile.type == TileType.FLAME) {
              Resolver.instance.resolve(tile, _this2.player);
            } else {
              Resolver.instance.resolve(_this2.player, tile);
            }
          });
        };
        _proto.checkMoveLeft = function checkMoveLeft() {
          var _this3 = this;
          var leftDown = MapManager.instance.getTiles(this.player.minRow, this.player.minCol);
          var leftUp = MapManager.instance.getTiles(this.player.maxRow, this.player.minCol);
          var staticTiles = [];
          var otherTiels = [];
          leftUp.forEach(function (tile) {
            if (tile == _this3.player) {
              return;
            }
            if (tile.type == TileType.STATIC) {
              staticTiles.push(tile);
            } else {
              otherTiels.push(tile);
            }
          });
          leftDown.forEach(function (tile) {
            if (tile == _this3.player) {
              return;
            }
            if (tile.type == TileType.STATIC) {
              staticTiles.push(tile);
            } else {
              otherTiels.push(tile);
            }
          });
          var tiles = staticTiles.concat(otherTiels);
          tiles.forEach(function (tile) {
            if (tile.type == TileType.FLAME) {
              Resolver.instance.resolve(tile, _this3.player);
            } else {
              Resolver.instance.resolve(_this3.player, tile);
            }
          });
        };
        _proto.checkMoveUp = function checkMoveUp() {
          var _this4 = this;
          var leftUp = MapManager.instance.getTiles(this.player.maxRow, this.player.minCol);
          var rightUp = MapManager.instance.getTiles(this.player.maxRow, this.player.maxCol);
          var staticTiles = [];
          var otherTiels = [];
          rightUp.forEach(function (tile) {
            if (tile == _this4.player) {
              return;
            }
            if (tile.type == TileType.STATIC) {
              staticTiles.push(tile);
            } else {
              otherTiels.push(tile);
            }
          });
          leftUp.forEach(function (tile) {
            if (tile == _this4.player) {
              return;
            }
            if (tile.type == TileType.STATIC) {
              staticTiles.push(tile);
            } else {
              otherTiels.push(tile);
            }
          });
          var tiles = staticTiles.concat(otherTiels);
          tiles.forEach(function (tile) {
            if (tile.type == TileType.FLAME) {
              Resolver.instance.resolve(tile, _this4.player);
            } else {
              Resolver.instance.resolve(_this4.player, tile);
            }
          });
        };
        _proto.checkMoveDown = function checkMoveDown() {
          var _this5 = this;
          var leftDown = MapManager.instance.getTiles(this.player.minRow, this.player.minCol);
          var rightDown = MapManager.instance.getTiles(this.player.minRow, this.player.maxCol);
          var staticTiles = [];
          var otherTiels = [];
          leftDown.forEach(function (tile) {
            if (tile == _this5.player) {
              return;
            }
            if (tile.type == TileType.STATIC) {
              staticTiles.push(tile);
            } else {
              otherTiels.push(tile);
            }
          });
          rightDown.forEach(function (tile) {
            if (tile == _this5.player) {
              return;
            }
            if (tile.type == TileType.STATIC) {
              staticTiles.push(tile);
            } else {
              otherTiels.push(tile);
            }
          });
          var tiles = staticTiles.concat(otherTiels);
          tiles.forEach(function (tile) {
            if (tile.type == TileType.FLAME) {
              Resolver.instance.resolve(tile, _this5.player);
            } else {
              Resolver.instance.resolve(_this5.player, tile);
            }
          });
        };
        _proto.slide = function slide() {
          if (this.player.slideDir.y != 0 || this.player.slideDir.x != 0) {
            this.player.prePos.set(this.player.node.x, this.player.node.y);
            this.player.node.y += this.player.slideDir.y;
            this.player.node.x += this.player.slideDir.x;
            if (this.player.slideDir.y > 0) {
              this.player.realDir.set(0, 1);
              this.checkMoveUp();
            } else if (this.player.slideDir.y < 0) {
              this.player.realDir.set(0, -1);
              this.checkMoveDown();
            }
            if (this.player.slideDir.x > 0) {
              this.player.realDir.set(1, 0);
              this.checkMoveRight();
            } else if (this.player.slideDir.x < 0) {
              this.player.realDir.set(-1, 0);
              this.checkMoveLeft();
            }
          }
        };
        _proto.checkMove = function checkMove() {
          if (this.player.dir.equals2f(0, 0)) {
            this.stateMachine.setStateByName("StatePlayer101Idle");
          } else {
            //改变animation就可以了
            this.setAnimation();
            this.move();
            // if(this.player.dir.x != 0){//先左右、后上下
            //     if(this.preDir.x != this.player.dir.x){
            //         this.stateMachine.setStateByName("StatePlayer100Move", true);
            //     }
            // }else{
            //     if(this.preDir.y != this.player.dir.y){
            //         this.stateMachine.setStateByName("StatePlayer100Move", true);
            //     }
            // }
          }
        };

        return StatePlayer101Move;
      }(StateBase)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/StaticTile.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './Tile.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, Animation, Tile;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Animation = module.Animation;
    }, function (module) {
      Tile = module.Tile;
    }],
    execute: function () {
      var _dec, _dec2, _class, _class2, _descriptor;
      cclegacy._RF.push({}, "78820/MS1JD/JuSnZdfJjbb", "StaticTile", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var StaticTile = exports('StaticTile', (_dec = ccclass('StaticTile'), _dec2 = property(Animation), _dec(_class = (_class2 = /*#__PURE__*/function (_Tile) {
        _inheritsLoose(StaticTile, _Tile);
        function StaticTile() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Tile.call.apply(_Tile, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "animation", _descriptor, _assertThisInitialized(_this));
          return _this;
        }
        var _proto = StaticTile.prototype;
        _proto.start = function start() {};
        _proto.flameHit = function flameHit(flame) {
          if (!this.canFlameHit) return;
          if (this.isDead) return;
          this.isDead = true;
          this.animation.play();
        };
        _proto.deadEnd = function deadEnd() {
          this.destroySelf();
        };
        return StaticTile;
      }(Tile), _descriptor = _applyDecoratedDescriptor(_class2.prototype, "animation", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/StorageDataManager.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './aes.ts', './core.ts'], function (exports) {
  var _createClass, cclegacy, sys, AES, Utf8;
  return {
    setters: [function (module) {
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
      sys = module.sys;
    }, function (module) {
      AES = module.AES;
    }, function (module) {
      Utf8 = module.Utf8;
    }],
    execute: function () {
      cclegacy._RF.push({}, "3b2e42Lmi9G/InQDKbQVOfc", "StorageDataManager", undefined);
      var StorageDataManager = exports('StorageDataManager', /*#__PURE__*/function () {
        function StorageDataManager() {
          this._data = {};
          this._dataKey = "fizzycraft_jigsaw";
          this._version = "0.0.1";
          this._saveKey = this._dataKey + "_" + this._version;
          this._isDebug = true;
          this._canSave = false;
        }
        var _proto = StorageDataManager.prototype;
        _proto.setData = function setData(key, value) {
          this._data[key] = value;
          this.saveData();
        };
        _proto.setDatas = function setDatas(keys, values) {
          for (var i = 0; i < keys.length; ++i) {
            this._data[keys[i]] = values[i];
          }
          this.saveData();
        };
        _proto.getData = function getData(key, defalut) {
          if (defalut === void 0) {
            defalut = null;
          }
          if (this._data[key] == null || this._data[key] == undefined) {
            this._data[key] = defalut;
          }
          return this._data[key];
        };
        _proto.removeData = function removeData(key) {
          sys.localStorage.removeItem(key);
          this._data[key] = null;
          delete this._data[key];
        };
        _proto.saveData = function saveData() {
          if (!this._canSave) {
            return;
          }
          var str = JSON.stringify(this._data);
          if (!this._isDebug) {
            var token = AES.encrypt(str, this._saveKey, null).toString();
            sys.localStorage.setItem(this._saveKey, token);
          } else {
            sys.localStorage.setItem(this._saveKey, str);
          }
        };
        _proto.clear = function clear() {
          sys.localStorage.clear();
          this._data = {};
        };
        _proto.iniData = function iniData() {
          if (!this._isDebug) {
            try {
              var token = sys.localStorage.getItem(this._saveKey);
              if (!token) {
                this._data = {};
              } else {
                var data_decrypt = AES.decrypt(token, this._saveKey, null);
                var data = Utf8.stringify(data_decrypt);
                this._data = JSON.parse(data);
              }
            } catch (error) {
              this.clear();
            }
          } else {
            try {
              var strData = sys.localStorage.getItem(this._saveKey);
              if (!strData) {
                this._data = {};
              } else {
                this._data = JSON.parse(strData);
              }
            } catch (error) {
              this.clear();
            }
          }
        };
        _createClass(StorageDataManager, null, [{
          key: "instance",
          get: function get() {
            if (!StorageDataManager._instance) {
              StorageDataManager._instance = new StorageDataManager();
            }
            return StorageDataManager._instance;
          }
        }]);
        return StorageDataManager;
      }());
      StorageDataManager._instance = null;
      StorageDataManager.IS_MUSIC_ON = "IS_MUSIC_ON";
      StorageDataManager.IS_SOUND_ON = "IS_SOUND_ON";
      StorageDataManager.COINS = "COINS";
      StorageDataManager.GEMS = "GEMS";
      StorageDataManager.FRAGS = "FRAGS";
      StorageDataManager.FRAG_COST = "FRAG_COST";
      StorageDataManager.FRAG_INDEX = "FRAG_INDEX";
      StorageDataManager.WISH_LIST = "WISH_LIST";
      StorageDataManager.PACKS = "PACKS";
      StorageDataManager.PROGRESS_PACKS = "PROGRESS_PACKS";
      StorageDataManager.PUZZLES_DATA = "PUZZLES_DATA";
      StorageDataManager.FRAME_COLOR = "FRAME_COLOR";
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Test.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './PlayerConfigPanel.ts', './LevelManager.ts', './EventManager.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, Node, log, Component, PlayerConfigPanel, LevelManager, EventManager;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Node = module.Node;
      log = module.log;
      Component = module.Component;
    }, function (module) {
      PlayerConfigPanel = module.PlayerConfigPanel;
    }, function (module) {
      LevelManager = module.LevelManager;
    }, function (module) {
      EventManager = module.EventManager;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _class, _class2, _descriptor, _descriptor2;
      cclegacy._RF.push({}, "9af5cl2+UtBcJZxFBi52MCA", "Test", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var Test = exports('Test', (_dec = ccclass('Test'), _dec2 = property(PlayerConfigPanel), _dec3 = property(Node), _dec(_class = (_class2 = /*#__PURE__*/function (_Component) {
        _inheritsLoose(Test, _Component);
        function Test() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Component.call.apply(_Component, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "playerConfigPanel", _descriptor, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "gamePlayNode", _descriptor2, _assertThisInitialized(_this));
          return _this;
        }
        var _proto = Test.prototype;
        _proto.start = function start() {
          EventManager.instance.on(EventManager.LEVEL_LOADED, this.onLevelLoaded, this);
        };
        _proto.onLevelLoaded = function onLevelLoaded() {
          log("level loaded");
          this.gamePlayNode.addChild(LevelManager.instance.level.node);
        };
        _proto.onConfigButtonClick = function onConfigButtonClick() {
          this.playerConfigPanel.node.active = !this.playerConfigPanel.node.active;
        };
        _proto.onPlayButtohClick = function onPlayButtohClick() {
          LevelManager.instance.levelId = 1;
          LevelManager.instance.loadLevel();
        };
        _proto.update = function update(deltaTime) {};
        return Test;
      }(Component), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "playerConfigPanel", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "gamePlayNode", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      })), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/TickManager.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc'], function (exports) {
  var _createClass, cclegacy;
  return {
    setters: [function (module) {
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "4cf5eY85bhLa5Jgawpby2ax", "TickManager", undefined);
      var TickManager = exports('TickManager', /*#__PURE__*/function () {
        function TickManager() {
          this.list = [];
        }
        var _proto = TickManager.prototype;
        _proto.addToList = function addToList(tickable) {
          this.list.push(tickable);
        };
        _proto.removeFromList = function removeFromList(tickable) {
          var index = this.list.indexOf(tickable);
          if (index >= 0) {
            this.list.splice(index, 1);
          }
        };
        _createClass(TickManager, null, [{
          key: "instance",
          get: function get() {
            if (!TickManager._instance) {
              TickManager._instance = new TickManager();
            }
            return TickManager._instance;
          }
        }]);
        return TickManager;
      }());
      TickManager._instance = null;
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Tile.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './GlobalData.ts', './MapManager.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, _createClass, cclegacy, _decorator, Vec2, CCBoolean, Rect, Component, TileType, GlobalData, MapManager;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Vec2 = module.Vec2;
      CCBoolean = module.CCBoolean;
      Rect = module.Rect;
      Component = module.Component;
    }, function (module) {
      TileType = module.TileType;
      GlobalData = module.GlobalData;
    }, function (module) {
      MapManager = module.MapManager;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _dec4, _dec5, _class, _class2, _descriptor, _descriptor2, _descriptor3, _descriptor4;
      cclegacy._RF.push({}, "f2b29rjpkNFdrMdT7ZYFvBb", "Tile", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var Tile = exports('Tile', (_dec = ccclass('Tile'), _dec2 = property(Vec2), _dec3 = property(Vec2), _dec4 = property({
        type: TileType
      }), _dec5 = property(CCBoolean), _dec(_class = (_class2 = /*#__PURE__*/function (_Component) {
        _inheritsLoose(Tile, _Component);
        function Tile() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Component.call.apply(_Component, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "offset", _descriptor, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "size", _descriptor2, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "type", _descriptor3, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "canFlameHit", _descriptor4, _assertThisInitialized(_this));
          _this.isDead = false;
          _this.mapRefs = [];
          _this.collideRect = void 0;
          _this.prePos = new Vec2();
          return _this;
        }
        var _proto = Tile.prototype;
        _proto.onLoad = function onLoad() {
          this.collideRect = new CollideRect(this, new Rect(this.offset.x, this.offset.y, this.size.x, this.size.y));
        };
        _proto.flameHit = function flameHit(flame) {};
        _proto.destroySelf = function destroySelf() {
          this.removeFromMap();
          this.node.removeFromParent();
          this.destroy();
        };
        _proto.removeFromMap = function removeFromMap() {
          while (this.mapRefs.length > 0) {
            var ref = this.mapRefs.pop();
            MapManager.instance.removeTile(this, ref.row, ref.col);
          }
        };
        _proto.addToMap = function addToMap() {
          MapManager.instance.addTile(this, this.minRow, this.minCol);
          MapManager.instance.addTile(this, this.maxRow, this.maxCol);
          MapManager.instance.addTile(this, this.minRow, this.maxCol);
          MapManager.instance.addTile(this, this.maxRow, this.minCol);
        };
        _proto.updateMapPos = function updateMapPos() {
          var refCount = 0;
          for (var i = 0; i < this.mapRefs.length; i++) {
            var ref = this.mapRefs[i];
            if (ref.row == this.minRow && ref.col == this.minCol) {
              refCount++;
            }
            if (ref.row == this.maxRow && ref.col == this.maxCol) {
              refCount++;
            }
            if (ref.row == this.minRow && ref.col == this.maxCol) {
              refCount++;
            }
            if (ref.row == this.maxRow && ref.col == this.minCol) {
              refCount++;
            }
          }
          if (refCount == 4) {
            return;
          }
          this.removeFromMap();
          this.addToMap();
        };
        _createClass(Tile, [{
          key: "minColPre",
          get: function get() {
            return Math.floor(this.collideRect.xMinPre / GlobalData.TILE_WIDTH);
          }
        }, {
          key: "maxColPre",
          get: function get() {
            return Math.floor(this.collideRect.xMaxPre / GlobalData.TILE_WIDTH);
          }
        }, {
          key: "minRowPre",
          get: function get() {
            return Math.floor(this.collideRect.yMinPre / GlobalData.TILE_HEIGHT);
          }
        }, {
          key: "maxRowPre",
          get: function get() {
            return Math.floor(this.collideRect.yMaxPre / GlobalData.TILE_HEIGHT);
          }
        }, {
          key: "minCol",
          get: function get() {
            return Math.floor(this.collideRect.xMin / GlobalData.TILE_WIDTH);
          }
        }, {
          key: "maxCol",
          get: function get() {
            return Math.floor(this.collideRect.xMax / GlobalData.TILE_WIDTH);
          }
        }, {
          key: "minRow",
          get: function get() {
            return Math.floor(this.collideRect.yMin / GlobalData.TILE_HEIGHT);
          }
        }, {
          key: "maxRow",
          get: function get() {
            return Math.floor(this.collideRect.yMax / GlobalData.TILE_HEIGHT);
          }
        }, {
          key: "footRow",
          get: function get() {
            return Math.floor((this.collideRect.yMin + this.collideRect.yMax) * 0.5 / GlobalData.TILE_HEIGHT);
          }
        }, {
          key: "footCol",
          get: function get() {
            return Math.floor((this.collideRect.xMin + this.collideRect.xMax) * 0.5 / GlobalData.TILE_WIDTH);
          }
        }]);
        return Tile;
      }(Component), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "offset", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new Vec2();
        }
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "size", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new Vec2();
        }
      }), _descriptor3 = _applyDecoratedDescriptor(_class2.prototype, "type", [_dec4], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return TileType.STATIC;
        }
      }), _descriptor4 = _applyDecoratedDescriptor(_class2.prototype, "canFlameHit", [_dec5], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return false;
        }
      })), _class2)) || _class));
      var TileMapRef = exports('TileMapRef', function TileMapRef(tile, row, col) {
        this.row = -1;
        this.col = -1;
        this.tile = null;
        this.tile = tile;
        this.row = row;
        this.col = col;
      });
      var CollideRect = /*#__PURE__*/function () {
        function CollideRect(tile, rect) {
          //如果size是40，那么xMin = 0， xMax = 39
          this.rect = void 0;
          this.host = void 0;
          this.rect = rect;
          this.host = tile;
        }
        var _proto2 = CollideRect.prototype;
        _proto2.intersects = function intersects(other) {
          return this.xMin <= other.xMax && this.xMax >= other.xMin && this.yMin <= other.yMax && this.yMax >= other.yMin;
        };
        _createClass(CollideRect, [{
          key: "xMinPre",
          get: function get() {
            return this.rect.xMin + this.host.prePos.x;
          }
        }, {
          key: "xMaxPre",
          get: function get() {
            return this.rect.xMax - 1 + this.host.prePos.x;
          }
        }, {
          key: "yMinPre",
          get: function get() {
            return this.rect.yMin + this.host.prePos.y;
          }
        }, {
          key: "yMaxPre",
          get: function get() {
            return this.rect.yMax - 1 + this.host.prePos.y;
          }
        }, {
          key: "xMin",
          get: function get() {
            return this.rect.xMin + this.host.node.position.x;
          }
        }, {
          key: "xMax",
          get: function get() {
            return this.rect.xMax - 1 + this.host.node.position.x;
          }
        }, {
          key: "yMin",
          get: function get() {
            return this.rect.yMin + this.host.node.position.y;
          }
        }, {
          key: "yMax",
          get: function get() {
            return this.rect.yMax - 1 + this.host.node.position.y;
          }
        }]);
        return CollideRect;
      }();
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/UserData.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc'], function (exports) {
  var _createClass, cclegacy;
  return {
    setters: [function (module) {
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "c8ce6vQIrRMcJdEVulxmnMe", "UserData", undefined);
      var UserData = exports('UserData', /*#__PURE__*/function () {
        function UserData() {
          this.backpack = [11, 12];
        }
        _createClass(UserData, null, [{
          key: "instance",
          get: function get() {
            if (!UserData._instance) {
              UserData._instance = new UserData();
            }
            return UserData._instance;
          }
        }]);
        return UserData;
      }());
      UserData._instance = null;
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Utils.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc'], function (exports) {
  var _createClass, cclegacy, clamp;
  return {
    setters: [function (module) {
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
      clamp = module.clamp;
    }],
    execute: function () {
      cclegacy._RF.push({}, "3e99cd2zdNNUK9ffRzSwM3h", "Utils", undefined);
      var Utils = exports('Utils', /*#__PURE__*/function () {
        function Utils() {}
        var _proto = Utils.prototype;
        _proto.shuffleArray = function shuffleArray(arr, count, copy) {
          if (count === void 0) {
            count = 1;
          }
          if (copy === void 0) {
            copy = true;
          }
          var result;
          if (copy) {
            result = [].concat(arr);
          } else {
            result = arr;
          }
          for (var i = 0; i < count; ++i) {
            this.shuffle(result);
          }
          return result;
        };
        _proto.shuffle = function shuffle(arr) {
          for (var i = arr.length - 1; i > 0; --i) {
            var j = Math.floor(Math.random() * (i + 1));
            var _ref = [arr[j], arr[i]];
            arr[i] = _ref[0];
            arr[j] = _ref[1];
          }
        };
        _proto.moveToward = function moveToward(a, b, step) {
          var c = a + step;
          if (b >= a) {
            c = clamp(c, a, b);
          } else {
            c = clamp(c, b, a);
          }
          return c;
        };
        _createClass(Utils, null, [{
          key: "instance",
          get: function get() {
            if (!Utils._instance) {
              Utils._instance = new Utils();
            }
            return Utils._instance;
          }
        }]);
        return Utils;
      }());
      Utils._instance = null;
      cclegacy._RF.pop();
    }
  };
});

(function(r) {
  r('virtual:///prerequisite-imports/main', 'chunks:///_virtual/main'); 
})(function(mid, cid) {
    System.register(mid, [cid], function (_export, _context) {
    return {
        setters: [function(_m) {
            var _exportObj = {};

            for (var _key in _m) {
              if (_key !== "default" && _key !== "__esModule") _exportObj[_key] = _m[_key];
            }
      
            _export(_exportObj);
        }],
        execute: function () { }
    };
    });
});