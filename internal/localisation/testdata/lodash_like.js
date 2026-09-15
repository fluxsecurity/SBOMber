;(function() {

  var FUNC_ERROR_TEXT = 'Expected a function';

  var reForbiddenIdentifierChars = /[()=,{}\[\]\/\s]/;

  var runInContext = (function runInContext(context) {

    function template(string, options, guard) {
      var variable = options.variable;
      if (reForbiddenIdentifierChars.test(variable)) {
        throw new Error(FUNC_ERROR_TEXT);
      }
      return string;
    }

    function safeGet(object, key) {
      if (key == '__proto__') {
        return;
      }
      return object[key];
    }

    return { template: template };
  });

  var _ = runInContext();
  module.exports = _;
}.call(this));
