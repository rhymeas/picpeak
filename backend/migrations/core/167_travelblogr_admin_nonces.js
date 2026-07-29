/**
 * One-time nonce ledger for the short-lived TravelBlogr admin handoff.
 * The signed assertion travels in a form body, and its jti can be consumed
 * exactly once even when several backend instances are running.
 */
exports.up = async function up(knex) {
  if (await knex.schema.hasTable('travelblogr_admin_nonces')) return;

  await knex.schema.createTable('travelblogr_admin_nonces', (table) => {
    table.string('jti', 128).primary();
    table.timestamp('expires_at').notNullable().index();
    table.timestamp('created_at').notNullable().defaultTo(knex.fn.now());
  });
};

exports.down = async function down(knex) {
  if (await knex.schema.hasTable('travelblogr_admin_nonces')) {
    await knex.schema.dropTable('travelblogr_admin_nonces');
  }
};
