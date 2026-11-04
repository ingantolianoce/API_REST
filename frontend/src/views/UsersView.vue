<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, messageFor } from '../api/http'

interface UserRow { id: string; email: string; fullName: string; status: string; mfaEnabled: boolean; roles: string[] }
const users = ref<UserRow[]>([])
const error = ref('')

onMounted(async () => {
  try {
    users.value = await api<UserRow[]>('/api/v1/users?size=50')
  } catch (e) {
    error.value = messageFor(e)
  }
})
</script>

<template>
  <h1>Usuarios</h1>
  <p v-if="error" class="error" role="alert">{{ error }}</p>
  <table>
    <thead><tr><th>Nombre</th><th>Correo</th><th>Roles</th><th>Estado</th><th>MFA</th></tr></thead>
    <tbody>
      <!-- Interpolacion {{ }} escapa el HTML. Prohibido v-html con datos de usuario. -->
      <tr v-for="u in users" :key="u.id">
        <td>{{ u.fullName }}</td><td>{{ u.email }}</td><td>{{ u.roles.join(', ') }}</td><td>{{ u.status }}</td><td>{{ u.mfaEnabled ? 'Sí' : 'No' }}</td>
      </tr>
    </tbody>
  </table>
</template>
