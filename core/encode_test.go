// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package core_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

func TestEncodeAttesterFetchArg(t *testing.T) {
	attDuty1 := testutil.RandomAttestationDuty(t)

	arg1, err := core.EncodeAttesterFetchArg(attDuty1)
	require.NoError(t, err)

	attDuty2, err := core.DecodeAttesterFetchArg(arg1)
	require.NoError(t, err)

	arg2, err := core.EncodeAttesterFetchArg(attDuty2)
	require.NoError(t, err)

	require.Equal(t, attDuty1, attDuty2)
	require.Equal(t, arg1, arg2)
}

func TestEncodeProposerFetchArg(t *testing.T) {
	proDuty1 := testutil.RandomProposerDuty(t)

	arg1, err := core.EncodeProposerFetchArg(proDuty1)
	require.NoError(t, err)

	proDuty2, err := core.DecodeProposerFetchArg(arg1)
	require.NoError(t, err)

	arg2, err := core.EncodeProposerFetchArg(proDuty2)
	require.NoError(t, err)

	require.Equal(t, arg1, arg2)
	require.Equal(t, proDuty1, proDuty2)
}
