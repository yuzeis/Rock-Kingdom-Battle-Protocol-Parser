from __future__ import annotations

import unittest

import Data
import rkpp_analysis as analysis


class DataBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        Data.invalidate_cache()

    def test_skill_attr_buff_indexes_are_loaded(self) -> None:
        skill = Data.get_skill_meta(7030320)
        self.assertIsNotNone(skill)
        self.assertEqual(skill.get("name"), "酶浓度调整")
        self.assertEqual(Data.get_skill_name(703032000), "酶浓度调整")

        attr = Data.get_attr_meta(1)
        self.assertEqual(attr.get("name"), "生命")

        buff = Data.get_buff_meta(20010010)
        self.assertEqual(buff.get("name"), "物攻等级提升")
        self.assertIn("10%", buff.get("desc", ""))

    def test_pet_and_pb_indexes_are_loaded(self) -> None:
        pet = Data.get_pet_meta(2000605)
        self.assertEqual(pet.get("name"), "恶魔狼")

        pb = Data.get_opcode_pb_meta(4900)
        self.assertEqual(pb.get("message"), "ZoneBattlePerformStartNotify")
        self.assertTrue(str(pb.get("proto_file") or "").endswith(".proto"))

    def test_schema_enrichment_uses_data_bundle(self) -> None:
        obj = {
            "skill_id": 7030320,
            "buff_id": 20010010,
            "types": [1, 2],
            "pet_id": 2000605,
        }
        enriched = analysis._enrich_known_id_names(obj)
        self.assertEqual(enriched["skill_name"], "酶浓度调整")
        self.assertIn("skill_desc", enriched)
        self.assertEqual(enriched["buff_name"], "物攻等级提升")
        self.assertEqual(enriched["type_names"], ["生命", "物攻"])
        self.assertEqual(enriched["pet_name"], "恶魔狼")

    def test_lookup_opcode_includes_pb_reference(self) -> None:
        info = analysis.lookup_opcode(4900)
        self.assertEqual(info.get("pb_message"), "ZoneBattlePerformStartNotify")
        self.assertTrue(info.get("pb_proto_file"))

    def test_battle_blood_pet_skill_nested_schema_is_available(self) -> None:
        raw = {
            "fields": [
                {
                    "field": 1,
                    "wire": 2,
                    "sub": {
                        "fields": [
                            {"field": 1, "wire": 0, "value": 7000010},
                            {"field": 2, "wire": 0, "value": 401},
                            {"field": 3, "wire": 0, "value": 1},
                        ],
                    },
                },
                {
                    "field": 3,
                    "wire": 2,
                    "sub": {
                        "fields": [
                            {"field": 1, "wire": 0, "value": 7000030},
                            {"field": 2, "wire": 0, "value": 0},
                        ],
                    },
                },
            ],
        }

        decoded = analysis.decode_by_schema(raw, "BattleBloodPetSkill")

        self.assertEqual(decoded["pkinfo"]["skill_id"], 7000010)
        self.assertEqual(decoded["pkinfo"]["attack_pet_id"], 401)
        self.assertTrue(decoded["pkinfo"]["hide"])
        self.assertEqual(decoded["skills"][0]["skill_id"], 7000030)
        self.assertFalse(decoded["skills"][0]["hide"])


if __name__ == "__main__":
    unittest.main()
