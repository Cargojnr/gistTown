// models/Audio.js
import { DataTypes } from 'sequelize';
import sequelize from '../db.js';

const Audio = sequelize.define('Audio', {
  filename: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  path: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  url: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  uploadDate: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW,
  },
  userId: {
    type: DataTypes.INTEGER,
    allowNull: false,
},
reactions: {
  type: DataTypes.JSONB,
  defaultValue: {},
},
category: {
  type: DataTypes.STRING, // e.g. "public", "exclusive", etc.
  allowNull: false,
  defaultValue: "public",
},
type: {
  type: DataTypes.STRING, // e.g. "audio"
  allowNull: false,
  defaultValue: "audio",
}
},
{
  tableName: "audios" // This must match your actual DB table name
});

export default Audio;
