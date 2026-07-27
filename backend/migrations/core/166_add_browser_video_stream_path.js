/**
 * Browser-compatible MP4 derivative for videos whose original container or
 * codec is not consistently playable in Chrome, Safari, and Firefox.
 */
exports.up = async function (knex) {
  if (!(await knex.schema.hasTable('photos'))) return;
  if (!(await knex.schema.hasColumn('photos', 'stream_path'))) {
    await knex.schema.alterTable('photos', (table) => {
      table.string('stream_path', 512).nullable();
    });
  }
};

exports.down = async function (knex) {
  if (await knex.schema.hasTable('photos') && await knex.schema.hasColumn('photos', 'stream_path')) {
    await knex.schema.alterTable('photos', (table) => {
      table.dropColumn('stream_path');
    });
  }
};
