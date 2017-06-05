var register = function (Handlebars) {
    var helpers = {
        equal: function(lvalue, rvalue, options) {
            // console.log(lvalue.toString() + "              " + rvalue.toString());
            if (arguments.length < 3)
                throw new Error("Handlebars Helper equal needs 2 parameters");
            if( lvalue.toString()==rvalue.toString() ) {
                return options.fn(this);
            } else {
                return options.inverse(this);
            }
        }
    };

    if (Handlebars && typeof Handlebars.registerHelper === "function") {
        for (var prop in helpers) {
            Handlebars.registerHelper(prop, helpers[prop]);
        }
    } else {
        return helpers;
    }

};

module.exports.register = register;
module.exports.helpers = register(null);
