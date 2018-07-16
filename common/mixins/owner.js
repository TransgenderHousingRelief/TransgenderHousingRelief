'use strict';
module.exports = function(Model, options) {
  // get the user model
  var User = Model.getDataSource().models.User;
  // create relation to the User model and call it owner
  Model.belongsTo(User, {as: 'owner', foreignKey: 'ownerId'});

  // each time your model instance is saved, make sure the current user is set as the owner
  // need to do this for upsers too (code not here)
  Model.observe('before save', (ctx, next)=> {
    var instanceOrData = ctx.data ? 'data' : 'instance';
  ctx[instanceOrData].ownerId = ctx.options.accessToken.userId;
});

  // each time your model is accessed, add a where-clause to filter by the current user
  Model.observe('access', (ctx, next)=>{
    const userId = safeGet(ctx, 'options.accessToken.userId');
  if (!userId) return next();  // no access token, internal or test request;
  var userIdClause = {userId: userId};

  // this part is tricky because you may need to add
  // the userId filter to an existing where-clause

  ctx.query = ctx.query || {};
  if (ctx.query.where) {
    if (ctx.query.where.and) {
      if (!ctx.query.where.and.some((andClause)=>{
          return andClause.hasOwnProperty('userId');
    })) {
        ctx.query.where.and.push(userIdClause);
      }
    } else {
      if (!ctx.query.where.userId) {
        var tmpWhere = ctx.query.where;
        ctx.query.where = {};
        ctx.query.where.and = [tmpWhere, userIdClause];
      }
    }
  } else {
    ctx.query.where = userIdClause;
  }
  next();
});
};
