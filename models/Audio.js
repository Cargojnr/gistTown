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

}, 
{
  tableName: "audios" // This must match your actual DB table name
});

export default Audio;
