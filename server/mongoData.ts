import mongoose, { Schema, type Model } from 'mongoose';

export const dataTables = [
  'trainees',
  'employees',
  'trainingPrograms',
  'providers',
  'employers',
  'skills',
  'followups',
] as const;

export type DataTable = (typeof dataTables)[number];

const allowedTables = new Set<string>(dataTables);
const models = new Map<string, Model<any>>();

function getModel(table: string): Model<any> {
  if (!allowedTables.has(table)) {
    throw new Error(`Unknown data table: ${table}`);
  }

  const cached = models.get(table);
  if (cached) return cached;

  const schema = new Schema(
    { id: { type: String, required: true, unique: true } },
    {
      strict: false,
      versionKey: false,
      collection: table,
    }
  );

  const modelName = `SkillTrack_${table}`;
  const model =
    (mongoose.models[modelName] as Model<any> | undefined) ??
    mongoose.model(modelName, schema, table);

  models.set(table, model);
  return model;
}

import {
  getTableRecords,
  insertTableRecord,
  updateTableRecord,
  deleteTableRecord,
} from './db';

export async function listRecords<T>(table: string): Promise<T[]> {
  if (mongoose.connection.readyState !== 1) {
    return getTableRecords<T>(table);
  }
  return getModel(table)
    .find({}, { _id: 0, __v: 0 })
    .lean<T[]>()
    .exec();
}

export async function insertRecord<T extends { id: string }>(
  table: string,
  record: T
): Promise<void> {
  if (mongoose.connection.readyState !== 1) {
    return insertTableRecord<T>(table, record);
  }
  await getModel(table).create(record);
}

export async function updateRecord<T = Record<string, unknown>>(
  table: string,
  id: string,
  patch: Partial<T> | Record<string, unknown>
): Promise<T | null> {
  if (mongoose.connection.readyState !== 1) {
    return updateTableRecord<T>(table, id, patch as Record<string, unknown>);
  }
  const safePatch = { ...patch };
  delete (safePatch as Record<string, unknown>)._id;

  return getModel(table)
    .findOneAndUpdate(
      { id },
      { $set: safePatch },
      { new: true, runValidators: true }
    )
    .select({ _id: 0, __v: 0 })
    .lean<T>()
    .exec();
}

export async function deleteRecord(
  table: string,
  id: string
): Promise<boolean> {
  if (mongoose.connection.readyState !== 1) {
    return deleteTableRecord(table, id);
  }
  const result = await getModel(table).deleteOne({ id }).exec();
  return result.deletedCount === 1;
}